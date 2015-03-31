#import "YAV.h"
#import <sys/types.h>
#import <sys/socket.h>
#import <sys/un.h>

#define PATHSTOWATCH @[@"/Users/me/Download"]
#define LOGFILE "/Users/me/Library/Logs/scan.log"
#define SOCKET "/tmp/socket.socket"

@interface YAV () <NSStreamDelegate, NSUserNotificationCenterDelegate>
{
}

@property (readwrite) NSInputStream *inputStream;
@property (readwrite) NSOutputStream *outputStream;
@property (readwrite) NSMutableArray *buffer;
@property BOOL isWorking;
@property FILE *outFile;

void callback (ConstFSEventStreamRef, void *, size_t, void *, const FSEventStreamEventFlags[], const FSEventStreamEventId[]);
void print_eventFlag (FSEventStreamEventFlags);
BOOL shouldScanned (FSEventStreamEventFlags, NSString *);
-(BOOL)isolate:(NSString *)path;

@end

@implementation YAV

- (id)init
{
	FSEventStreamContext context;
	NSArray *pathsToWatch;
	FSEventStreamEventId sinceWhen;
	CFTimeInterval latency;
	FSEventStreamCreateFlags flags;
	FSEventStreamRef stream;

	self = [super init];
	if (self)
	{
		context = (FSEventStreamContext){0x0, (__bridge void *)self, NULL, NULL, NULL};
		pathsToWatch = PATHSTOWATCH;
		sinceWhen = kFSEventStreamEventIdSinceNow;
		latency = 0.0;
		flags = kFSEventStreamCreateFlagUseCFTypes
			| kFSEventStreamCreateFlagFileEvents;
		stream = FSEventStreamCreate
			(
				NULL,
				&callback,
				&context,
				(__bridge CFArrayRef)pathsToWatch,
				sinceWhen,
				latency,
				flags
				);
		FSEventStreamScheduleWithRunLoop
			(
				stream,
				CFRunLoopGetCurrent(),
				kCFRunLoopDefaultMode
				);

		self.outFile = fopen (LOGFILE, "a");
		assert (self.outFile != NULL);
		
		self.buffer = [NSMutableArray array];
		self.isWorking = NO;
		FSEventStreamStart (stream);
	}

	return self;
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
	[[NSUserNotificationCenter defaultUserNotificationCenter] setDelegate:self];
}

- (void)connectSocket
{
	NSRunLoop *loop;
	int sck;
	int ret;
	struct sockaddr_un address;
	CFReadStreamRef readStream;
	CFWriteStreamRef writeStream;

	if (self.isWorking)
	{
		return;
	}
	self.isWorking = YES;

	sck = socket (PF_LOCAL, SOCK_STREAM, 0);
	assert (sck >= 0);
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, SOCKET, 104);
	address.sun_len = SUN_LEN(&address);
	ret = connect (sck, (struct sockaddr *)&address, address.sun_len);
	assert (ret == 0);
	CFStreamCreatePairWithSocket (NULL, sck, &readStream, &writeStream);
	self.inputStream = (__bridge NSInputStream *)readStream;
	self.outputStream = (__bridge NSOutputStream *)writeStream;
	[self.inputStream setDelegate:self];
	[self.outputStream setDelegate:self];
	loop = [NSRunLoop currentRunLoop];
	[self.inputStream scheduleInRunLoop:loop
								forMode:NSDefaultRunLoopMode];
	[self.outputStream scheduleInRunLoop:loop
								 forMode:NSDefaultRunLoopMode];
	[self.inputStream open];
	[self.outputStream open];
}

- (void)closeStream
{
	NSRunLoop *loop;

	loop = [NSRunLoop currentRunLoop];
	[self.inputStream close];
	[self.inputStream removeFromRunLoop:loop
								forMode:NSDefaultRunLoopMode];
	self.inputStream = nil;

	if ( self.outputStream != nil )
	{
		[self closeOutputStream];
	}

	self.isWorking = NO;
	if ([self.buffer count] != 0)
	{
		[self connectSocket];
	}
}

- (void)closeOutputStream
{
	NSRunLoop *loop;

	loop = [NSRunLoop currentRunLoop];
	[self.outputStream close];
	[self.outputStream removeFromRunLoop:loop
								 forMode:NSDefaultRunLoopMode];
	self.outputStream = nil;

	if ( self.inputStream == nil )
	{
		self.isWorking = NO;
		if ([self.buffer count] != 0)
		{
			[self connectSocket];
		}
	}
}

- (void)stream:(NSStream *)theStream handleEvent:(NSStreamEvent)streamEvent
{
	char charbuf[8192];
	char *p;
	uint8_t buf[1024];
	unsigned int len = 0;
	NSError *theError;
	char path[8192];
	char virus[8192];
	NSUserNotification *notification;
	NSAlert *alert;
	NSModalResponse res;
	
	switch (streamEvent)
	{
	case NSStreamEventHasBytesAvailable:
		len = [(NSInputStream *)theStream read:buf maxLength:1024];
		if (len)
		{
			buf[len] = '\0';
			fprintf (self.outFile, "%s", buf);
			fflush (self.outFile);
			switch (buf[len-2])
			{
			case 'D' : /* FOUND */
				p = strrchr((const char *)buf, ' ');
				assert (p != NULL);
				*p = '\0';
				p = strrchr((const char *)buf, ' ');
				assert (p != NULL);
				strcpy (virus, p+1);
				*(p-1) = '\0';
				strcpy (path, (const char *)buf);

				notification = [[NSUserNotification alloc] init];
				notification.informativeText = [NSString stringWithFormat:@"A virus %s is found.", virus];
				notification.title = @"Virus found";
				[[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:notification];
				
				alert = [[NSAlert alloc] init];
				alert.messageText = @"Virus found";
				alert.informativeText = [NSString stringWithFormat:@"File %s contains a virus %s. Can i move the file to Trash?", path, virus];
				alert.alertStyle = NSCriticalAlertStyle;
				[alert addButtonWithTitle:@"OK"];
				[alert addButtonWithTitle:@"Cancel"];

				res = [alert runModal];

				[[NSUserNotificationCenter defaultUserNotificationCenter] removeDeliveredNotification:notification];
				notification = nil;
				if (res == NSAlertFirstButtonReturn)
				{
					[self isolate:[NSString stringWithUTF8String:path]];
				}
				break;
			case 'K' : /* OK */
			default : /* Error */
				break;
			}
		}
		else
		{
			[self closeStream];
		}
		
		break;
	case NSStreamEventHasSpaceAvailable:
		memset(charbuf, 0x0, 8192);
		while ([self.buffer count] != 0 && ![[NSFileManager defaultManager] fileExistsAtPath:self.buffer[0] isDirectory:NULL])
		{
			[self.buffer removeObjectAtIndex:0];
		}
		if ([self.buffer count] == 0)
		{
			break;
		}
		assert (strlen([self.buffer[0] cStringUsingEncoding:NSUTF8StringEncoding]) < 8192);
		sprintf(charbuf, "CONTSCAN %s", [self.buffer[0] cStringUsingEncoding:NSUTF8StringEncoding]);
		[self.buffer removeObjectAtIndex:0];
		memset(buf, 0x0, 1024);
		memcpy(buf, charbuf, 1024);
		[(NSOutputStream *)theStream write:buf maxLength:1024];
		[self closeOutputStream];
		break;
	case NSStreamEventOpenCompleted:
		break;
	case NSStreamEventNone:
		break;
	case NSStreamEventErrorOccurred:
		theError = [theStream streamError];
		NSLog(@"%li : %@", [theError code], [theError localizedDescription]);
		[self closeStream];
		break;
	case NSStreamEventEndEncountered:
		[self closeStream];
		break;
	}
}

void callback
(
	ConstFSEventStreamRef streamRef,
	void *clientCallBackInfo,
	size_t numEvents,
	void *eventPaths,
	const FSEventStreamEventFlags eventFlags[],
	const FSEventStreamEventId eventIds[]
	)
{
	size_t i;
	NSArray *paths;
	YAV *self;

	self = (__bridge YAV *)clientCallBackInfo;
	paths = (__bridge NSArray *)eventPaths;

	for (i=0; i<numEvents; i++)
	{
		if (shouldScanned(eventFlags[i], paths[i]))
		{
			[self.buffer addObject:paths[i]];
		}
	}
	if ([self.buffer count] != 0)
	{
		[self connectSocket];
	}
}

void print_eventFlag(FSEventStreamEventFlags flag)
{
	if ( flag == kFSEventStreamEventFlagNone )
	{
		printf ("None\n");
		return;
	}
	if ( flag & kFSEventStreamEventFlagMustScanSubDirs )
	{
		printf ("MustScanSubDirs ");
	}
	if ( flag & kFSEventStreamEventFlagUserDropped )
	{
		printf ("UserDropped ");
	}
	if ( flag & kFSEventStreamEventFlagKernelDropped )
	{
		printf ("KernelDropped ");
	}
	if ( flag & kFSEventStreamEventFlagEventIdsWrapped )
	{
		printf ("EventIdsWrapped ");
	}
	if ( flag & kFSEventStreamEventFlagHistoryDone )
	{
		printf ("HistoryDone ");
	}
	if ( flag & kFSEventStreamEventFlagRootChanged )
	{
		printf ("RootChanged ");
	}
	if ( flag & kFSEventStreamEventFlagMount )
	{
		printf ("Mount ");
	}
	if ( flag & kFSEventStreamEventFlagUnmount )
	{
		printf ("Unmount ");
	}
	if ( flag & kFSEventStreamEventFlagItemCreated )
	{
		printf ("ItemCreated ");
	}
	if ( flag & kFSEventStreamEventFlagItemRemoved )
	{
		printf ("ItemRemoved ");
	}
	if ( flag & kFSEventStreamEventFlagItemInodeMetaMod )
	{
		printf ("ItemInodeMetaMod ");
	}
	if ( flag & kFSEventStreamEventFlagItemRenamed )
	{
		printf ("ItemRenamed ");
	}
	if ( flag & kFSEventStreamEventFlagItemModified )
	{
		printf ("ItemModified ");
	}
	if ( flag & kFSEventStreamEventFlagItemFinderInfoMod )
	{
		printf ("ItemFinderInfoMod ");
	}
	if ( flag & kFSEventStreamEventFlagItemChangeOwner )
	{
		printf ("ItemChangeOwner ");
	}
	if ( flag & kFSEventStreamEventFlagItemXattrMod )
	{
		printf ("ItemXattrMod ");
	}
	if ( flag & kFSEventStreamEventFlagItemIsFile )
	{
		printf ("ItemIsFile ");
	}
	if ( flag & kFSEventStreamEventFlagItemIsDir )
	{
		printf ("ItemIsDir ");
	}
	if ( flag & kFSEventStreamEventFlagItemIsSymlink )
	{
		printf ("ItemIsSymlink ");
	}
	printf ("\n");
	fflush(stdout);
}

BOOL shouldScanned (FSEventStreamEventFlags flag, NSString *path)
{
	if ( flag == kFSEventStreamEventFlagNone )
	{
		return NO;
	}
	if ( flag & kFSEventStreamEventFlagItemCreated )
	{
		return YES;
	}
	if ( flag & kFSEventStreamEventFlagItemRemoved )
	{
		return NO;
	}
	if ( flag & kFSEventStreamEventFlagItemInodeMetaMod )
	{
	}
	if ( flag & kFSEventStreamEventFlagItemRenamed )
	{
		return YES;
	}
	if ( flag & kFSEventStreamEventFlagItemModified )
	{
		return YES;
	}
	if ( flag & kFSEventStreamEventFlagItemFinderInfoMod )
	{
	}
	if ( flag & kFSEventStreamEventFlagItemChangeOwner )
	{
	}
	if ( flag & kFSEventStreamEventFlagItemXattrMod )
	{
	}
	if ( flag & kFSEventStreamEventFlagItemIsFile )
	{
	}
	if ( flag & kFSEventStreamEventFlagItemIsDir )
	{
	}
	if ( flag & kFSEventStreamEventFlagItemIsSymlink )
	{
	}

	return NO;
}

-(BOOL)isolate:(NSString *)path
{
	NSURL *url;
	
	url = [NSURL fileURLWithPath:path];
	return [[NSFileManager defaultManager] trashItemAtURL:url
										 resultingItemURL:nil
													error:nil];
   
}

- (BOOL)userNotificationCenter:(NSUserNotificationCenter *)center
	 shouldPresentNotification:(NSUserNotification *)notification
{
	return YES;
}
	
@end
