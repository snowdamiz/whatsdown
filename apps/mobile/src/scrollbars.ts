export function installScrollbars(document: Document): () => void {
  const animations = new Map<Element, Animation>();
  const reducedMotion = document.defaultView?.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const onScroll = (event: Event) => {
    if (!(event.target instanceof Element)) return;
    const target = event.target;
    animations.get(target)?.cancel();
    const animation = target.animate(
      { '--scrollbar-color': ['var(--scrollbar-thumb)', 'transparent'] },
      { delay: 600, duration: reducedMotion ? 0 : 240, easing: 'ease-out', fill: 'backwards' },
    );
    animations.set(target, animation);
    animation.onfinish = () => { animations.delete(target); };
  };
  document.addEventListener('scroll', onScroll, { capture: true, passive: true });
  return () => {
    document.removeEventListener('scroll', onScroll, { capture: true });
    for (const animation of animations.values()) animation.cancel();
    animations.clear();
  };
}
