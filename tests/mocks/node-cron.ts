// Minimal Jest mock for node-cron used in unit tests
// Provides schedule() that returns an object with start/stop methods and unref handling

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const cron = {
  schedule: (/* pattern: string, task: () => void, options?: any */) => {
    let running = false;
    return {
      start: () => { running = true; },
      stop: () => { running = false; },
      getStatus: () => running,
      // mimic Node timers' unref no-op
      // eslint-disable-next-line @typescript-eslint/no-empty-function
      unref: () => {}
    } as unknown as NodeJS.Timeout;
  }
};

export default cron;
export const schedule = cron.schedule;