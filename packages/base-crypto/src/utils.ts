export const toArray = <T>(val?: T | T[]): T[] => {
  return val == null ? [] : Array.isArray(val) ? val : [val];
};
