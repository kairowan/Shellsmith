import Darwin
import Foundation

enum ProtectedResourceClock {
    private static let secondsPerTick: Double = {
        var scale = mach_timebase_info_data_t()
        mach_timebase_info(&scale)
        return Double(scale.numer) / Double(scale.denom) / 1_000_000_000
    }()

    // mach_continuous_time 的计数包含系统睡眠，避免恢复前台后把租约延长。
    static var now: TimeInterval { Double(mach_continuous_time()) * secondsPerTick }
}
