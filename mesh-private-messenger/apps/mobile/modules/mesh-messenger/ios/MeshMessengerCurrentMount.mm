#import "MeshMessengerCurrentMount.h"

#import <React_RCTAppDelegate/RCTReactNativeFactory.h>
#import <React_RCTAppDelegate/RCTRootViewFactory.h>
#import <ReactCommon/RCTHost.h>
#import <React/RCTComponentViewRegistry.h>
#import <React/RCTFabricSurface.h>
#import <React/RCTMountingManager.h>
#import <React/RCTSurfaceHostingView.h>
#import <React/RCTSurfacePresenter.h>
#import <React/RCTSurfaceProtocol.h>

#include <limits>

@interface MeshMessengerCurrentMountSnapshot ()
- (instancetype)initWithFactory:(RCTReactNativeFactory *)factory
                           root:(RCTSurfaceHostingView *)root
                          owner:(UIView *)owner
                           host:(RCTHost *)host
                      presenter:(RCTSurfacePresenter *)presenter
                        surface:(id<RCTSurfaceProtocol>)surface;
@end

@implementation MeshMessengerCurrentMountSnapshot {
  __weak RCTReactNativeFactory *_factory;
  __weak RCTSurfaceHostingView *_root;
  __weak UIView *_owner;
  __weak RCTHost *_host;
  __weak RCTSurfacePresenter *_presenter;
  __weak id<RCTSurfaceProtocol> _surface;
  __weak UIWindow *_window;
  __weak UIWindowScene *_scene;
  NSInteger _ownerTag;
  NSInteger _rootTag;
}

- (instancetype)initWithFactory:(RCTReactNativeFactory *)factory
                           root:(RCTSurfaceHostingView *)root
                          owner:(UIView *)owner
                           host:(RCTHost *)host
                      presenter:(RCTSurfacePresenter *)presenter
                        surface:(id<RCTSurfaceProtocol>)surface
{
  if ((self = [super init])) {
    _factory = factory; _root = root; _owner = owner; _host = host;
    _presenter = presenter; _surface = surface;
    _window = root.window; _scene = root.window.windowScene;
    _ownerTag = owner.tag; _rootTag = surface.rootTag;
  }
  return self;
}

- (BOOL)isCurrent
{
  if (![NSThread isMainThread]) { return NO; }
  // Strong locals are limited to this synchronous observation. The snapshot
  // never prolongs a factory, runtime, presenter, surface or native view.
  RCTReactNativeFactory *factory = _factory;
  RCTSurfaceHostingView *root = _root;
  UIView *owner = _owner;
  RCTHost *host = _host;
  RCTSurfacePresenter *presenter = _presenter;
  id<RCTSurfaceProtocol> surface = _surface;
  UIWindow *window = _window;
  UIWindowScene *scene = _scene;
  if (!factory || !root || !owner || !host || !presenter || !surface || !window || !scene ||
      factory.rootViewFactory.reactHost != host || host.surfacePresenter != presenter ||
      root.surface != surface || surface.rootTag != _rootTag || owner.tag != _ownerTag ||
      root.window != window || owner.window != window || window.windowScene != scene ||
      (owner != root && ![owner isDescendantOfView:root])) { return NO; }
  if (_ownerTag <= 0 || _ownerTag > std::numeric_limits<facebook::react::Tag>::max() ||
      [presenter surfaceForRootTag:_rootTag] != surface) { return NO; }
  RCTComponentViewRegistry *registry = presenter.mountingManager.componentViewRegistry;
  if (!registry || [registry findComponentViewWithTag:static_cast<facebook::react::Tag>(_ownerTag)] != owner) {
    return NO;
  }
  // Same host can replace its presenter. Re-read the current native chain after
  // the canonical registry lookup, instead of treating host identity as fresh.
  return factory.rootViewFactory.reactHost == host && host.surfacePresenter == presenter &&
      root.surface == surface && surface.rootTag == _rootTag &&
      [presenter surfaceForRootTag:_rootTag] == surface && owner.tag == _ownerTag &&
      root.window == window && owner.window == window && window.windowScene == scene;
}
@end

@implementation MeshMessengerCurrentMount
+ (MeshMessengerCurrentMountSnapshot *)captureWithFactory:(NSObject *)factoryObject
                                                   root:(UIView *)rootView
                                                  owner:(UIView *)owner
{
  if (![NSThread isMainThread] || ![factoryObject isKindOfClass:[RCTReactNativeFactory class]] ||
      ![rootView isKindOfClass:[RCTSurfaceHostingView class]]) { return nil; }
  RCTReactNativeFactory *factory = (RCTReactNativeFactory *)factoryObject;
  RCTSurfaceHostingView *root = (RCTSurfaceHostingView *)rootView;
  RCTHost *host = factory.rootViewFactory.reactHost;
  RCTSurfacePresenter *presenter = host.surfacePresenter;
  id<RCTSurfaceProtocol> surface = root.surface;
  if (!host || !presenter || !surface) { return nil; }
  MeshMessengerCurrentMountSnapshot *snapshot = [[MeshMessengerCurrentMountSnapshot alloc]
      initWithFactory:factory root:root owner:owner host:host presenter:presenter surface:surface];
  return [snapshot isCurrent] ? snapshot : nil;
}
@end
