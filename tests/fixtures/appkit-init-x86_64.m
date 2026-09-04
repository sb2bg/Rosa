#import <AppKit/AppKit.h>
#include <stdio.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        printf("APP %s\n", [NSStringFromClass([app class]) UTF8String]);
        [app terminate:nil];
    }
    printf("APPKIT INIT OK\n");
    return 0;
}
