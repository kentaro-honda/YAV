@import Cocoa;
#import "YAV.h"

int main(void)
{
	YAV *c;
	
	@autoreleasepool{
		[NSApplication sharedApplication];
		c = [[YAV alloc] init];
		[[NSApplication sharedApplication] setDelegate:c];
		[NSApp run];
	}
	return 0;
}
