#import "AvatarCodec.h"
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#include <math.h>
#include <string.h>

@interface MDEncodedAvatar : NSObject
@property(nonatomic,strong) NSMutableData *jpeg;
@end
@implementation MDEncodedAvatar
- (void)dealloc { if (_jpeg.length) memset(_jpeg.mutableBytes,0,_jpeg.length); }
@end
static BOOL MDImageExtent(NSDictionary *properties,double *width,double *height) {
    id w=properties[(id)kCGImagePropertyPixelWidth],h=properties[(id)kCGImagePropertyPixelHeight];
    if (![w isKindOfClass:NSNumber.class] || ![h isKindOfClass:NSNumber.class]) return NO;
    *width=[w doubleValue];*height=[h doubleValue];
    return isfinite(*width) && isfinite(*height) && *width>=1 && *height>=1 && floor(*width)==*width && floor(*height)==*height &&
        *width<=16384 && *height<=16384 && *width * *height<=64000000;
}
static MDEncodedAvatar *MDEncode(MDPrivateScope scope,const uint8_t *bytes,uint64_t length) {
    if (!scope.current(scope.context)) return nil;
    NSData *input=[NSData dataWithBytesNoCopy:(void *)bytes length:(NSUInteger)length freeWhenDone:NO];
    NSDictionary *noCache=@{(id)kCGImageSourceShouldCache:@NO};
    CGImageSourceRef source=CGImageSourceCreateWithData((__bridge CFDataRef)input,(__bridge CFDictionaryRef)noCache);
    if (source==NULL) return nil;
    CGImageRef thumbnail=NULL,crop=NULL,image=NULL;CGContextRef context=NULL;CGColorSpaceRef color=NULL;
    NSMutableData *rgba=nil;MDEncodedAvatar *result=nil;
    @try {
        if (CGImageSourceGetCount(source)==0 || CGImageSourceGetCount(source)>256) return nil;
        NSDictionary *properties=CFBridgingRelease(CGImageSourceCopyPropertiesAtIndex(source,0,(__bridge CFDictionaryRef)noCache));
        double width=0,height=0;if (!MDImageExtent(properties,&width,&height) || !scope.current(scope.context)) return nil;
        // The thumbnail is bounded before raster allocation. Limit metadata to
        // 64 MP / 16384 per axis, then decode at most 4096 on the long edge and 160
        // on the short edge before the centered square crop. OS codec-internal
        // allocations/caches are not claimed to be caller-wipeable.
        NSUInteger maximum=(NSUInteger)fmin(4096,ceil(fmax(width,height)/fmin(width,height)*160));
        NSDictionary *options=@{(id)kCGImageSourceCreateThumbnailFromImageAlways:@YES,(id)kCGImageSourceCreateThumbnailWithTransform:@YES,
            (id)kCGImageSourceThumbnailMaxPixelSize:@(maximum),(id)kCGImageSourceShouldCache:@NO};
        thumbnail=CGImageSourceCreateThumbnailAtIndex(source,0,(__bridge CFDictionaryRef)options);
        if (thumbnail==NULL || !scope.current(scope.context)) return nil;
        size_t w=CGImageGetWidth(thumbnail),h=CGImageGetHeight(thumbnail),side=MIN(w,h);
        if (side==0 || w>4096 || h>4096 || w*h>4096*160) return nil;
        crop=CGImageCreateWithImageInRect(thumbnail,CGRectMake((w-side)/2,(h-side)/2,side,side));if (crop==NULL) return nil;
        rgba=[NSMutableData dataWithLength:160*160*4];color=CGColorSpaceCreateWithName(kCGColorSpaceSRGB);if (color==NULL) return nil;
        context=CGBitmapContextCreate(rgba.mutableBytes,160,160,8,160*4,color,kCGImageAlphaPremultipliedLast|kCGBitmapByteOrder32Big);
        if (context==NULL) return nil;
        CGContextSetRGBFillColor(context,1,1,1,1);CGContextFillRect(context,CGRectMake(0,0,160,160));
        CGContextSetInterpolationQuality(context,kCGInterpolationHigh);CGContextDrawImage(context,CGRectMake(0,0,160,160),crop);
        if (!scope.current(scope.context)) return nil;
        image=CGBitmapContextCreateImage(context);if (image==NULL) return nil;
        for (NSNumber *quality in @[@0.7,@0.45,@0.2]) {
            if (!scope.current(scope.context)) return nil;
            NSMutableData *jpeg=[NSMutableData new];
            CGImageDestinationRef destination=CGImageDestinationCreateWithData((__bridge CFMutableDataRef)jpeg,(__bridge CFStringRef)UTTypeJPEG.identifier,1,NULL);
            if (destination==NULL) return nil;
            CGImageDestinationAddImage(destination,image,(__bridge CFDictionaryRef)@{(id)kCGImageDestinationLossyCompressionQuality:quality});
            BOOL done=CGImageDestinationFinalize(destination);CFRelease(destination);
            if (done && jpeg.length>0 && jpeg.length<=9198 && scope.current(scope.context)) { result=[MDEncodedAvatar new];result.jpeg=jpeg;break; }
            if (jpeg.length) memset(jpeg.mutableBytes,0,jpeg.length);
        }
    } @finally {
        if (image) CGImageRelease(image);if (context) CGContextRelease(context);
        if (color) CGColorSpaceRelease(color);if (crop) CGImageRelease(crop);if (thumbnail) CGImageRelease(thumbnail);CFRelease(source);
        if (rgba.length) memset(rgba.mutableBytes,0,rgba.length);
    }
    return result;
}
void *MDNativeAvatarEncode(MDPrivateScope scope,const uint8_t *bytes,uint64_t length) {
    if (scope.context==NULL || scope.retain==NULL || scope.release==NULL || scope.current==NULL || bytes==NULL || length==0 || length>20971520) return NULL;
    scope.retain(scope.context);
    @try { @autoreleasepool { return (__bridge_retained void *)MDEncode(scope,bytes,length); } }
    @catch (NSException *error) { (void)error;return NULL; }
    @finally { scope.release(scope.context); }
}
const uint8_t *MDNativeAvatarBytes(void *raw,uint64_t *length) {
    if (raw==NULL || length==NULL) return NULL;MDEncodedAvatar *value=(__bridge MDEncodedAvatar *)raw;*length=value.jpeg.length;return value.jpeg.bytes;
}
void MDNativeAvatarRelease(void *raw) { if (raw!=NULL) CFRelease(raw); }
