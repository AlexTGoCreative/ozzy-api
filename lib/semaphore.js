// Counting semaphore — bounds how many async tasks run concurrently.
//
// The native Agatha engines are loaded once and then scanned through koffi's
// asynchronous interface, which dispatches each call to a koffi worker thread.
// koffi by itself would let an unbounded number of calls queue up (up to
// max_async_calls), which on the heavy file engine (~12 GB resident model +
// per-scan feature-extraction working set) could exhaust memory. This semaphore
// caps the number of in-flight scans to a fixed worker count (default 8), so the
// engine is loaded once and served by a bounded pool of concurrent scans — the
// counting-semaphore generalisation of a single-scan mutex.
class Semaphore {
  constructor(max) {
    this.max = Math.max(1, Number.isFinite(max) ? Math.floor(max) : 1);
    this.active = 0;
    this.queue = [];
  }

  acquire() {
    if (this.active < this.max) {
      this.active++;
      return Promise.resolve();
    }
    return new Promise((resolve) => this.queue.push(resolve));
  }

  release() {
    const next = this.queue.shift();
    if (next) {
      // Hand the just-freed slot directly to the next waiter (active stays put).
      next();
    } else {
      this.active--;
    }
  }

  // Run `fn` once a slot is free, always releasing the slot afterwards.
  async run(fn) {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  // Introspection for health/diagnostics endpoints.
  stats() {
    return { max: this.max, active: this.active, queued: this.queue.length };
  }
}

module.exports = Semaphore;
