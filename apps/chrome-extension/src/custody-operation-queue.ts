/** One FIFO for custody and global mutations. A failed recovery barrier denies
 * future operations; ordinary operation errors do not poison the queue. */
export function createCustodyOperationQueue() {
  let tail:Promise<unknown>=Promise.resolve(),barrier:Promise<void>=Promise.resolve();
  return {
    setBarrier(value:Promise<void>){barrier=value;void value.catch(()=>{});},
    run<T>(operation:()=>Promise<T>):Promise<T>{
      const guarded=async()=>{await barrier;return operation();};
      const result=tail.then(guarded,guarded);tail=result.then(()=>{},()=>{});return result;
    },
  };
}
