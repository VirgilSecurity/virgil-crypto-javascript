export const memoizePromise = <T>(
  func: (...args: any[]) => Promise<T>,
  keySerializer?: (args: any[]) => string,
) => {
  const cache = new Map<string, Promise<T>>();
  return (...args: any[]) => {
    const key = keySerializer ? keySerializer(args) : JSON.stringify(args);
    if (cache.has(key)) {
      return cache.get(key)!;
    }
    const promise = func(...args);
    cache.set(key, promise);
    return promise;
  };
};
