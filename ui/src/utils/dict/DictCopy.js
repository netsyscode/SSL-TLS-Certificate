
// Clone the 'dict' object or array from an observer to an actual object or array.
// Note: Using setTimeout outside to defer the operation allows time for data to be retrieved from the backend.
export function deepCopyDict(target, map = new Map()) {
    if (typeof target === 'object') {
        let cloneTarget = Array.isArray(target) ? [] : {};
        if (map.get(target)) {
          return map.get(target);
        }
        map.set(target, cloneTarget);
        for (const key in target) {
          cloneTarget[key] = deepCopyDict(target[key], map);
        }
        return cloneTarget;
      } else {
        return target;
    }
}


export async function retriveDictMap(target) {
  return new Promise(resolve => {
    setTimeout(() => {
      const result = deepCopyDict(target);
      resolve(result);
    }, 250);
  });
}
