#import <Foundation/Foundation.h>
#include <stdio.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSString *hello = @"hello";
        NSString *target = [NSString stringWithFormat:@"%@, %@", hello, @"rosa"];
        NSString *shouted = [[target stringByAppendingString:@"!"] uppercaseString];
        printf("%s %lu\n", [shouted UTF8String], (unsigned long)[shouted length]);
    }
    return 0;
}
