/**
 * ClusterFuzz writes an access of more than one size as "{*}", so a crash type can read
 * "Heap-buffer-overflow WRITE {*}". On the page that looks like an unfilled template, so it is shown
 * as "(any size)". Evidence panels keep the raw value.
 */
export function displayCrashType(crashType: string): string {
  return crashType.replace(/\s*\{\*\}/g, " (any size)");
}
