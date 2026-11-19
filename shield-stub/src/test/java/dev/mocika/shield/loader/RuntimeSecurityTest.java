package dev.mocika.shield.loader;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class RuntimeSecurityTest {

    @Test
    public void 远程撤销只限制保护访问但保留独立环境阻断() throws Exception {
        java.lang.reflect.Field flag = RuntimeSecurity.class.getDeclaredField("remoteRevoked");
        flag.setAccessible(true);
        flag.setBoolean(null, true);
        try {
            assertEquals(false, RuntimeSecurity.shouldReject(8, true));
            assertEquals(true, RuntimeSecurity.shouldReject(1 | 8, false));
            assertEquals(true, RuntimeSecurity.shouldReject(2 | 8, true));
        } finally { flag.setBoolean(null, false); }
    }

    @Test
    public void 详细信号保持原阻断策略且不混淆检测来源() {
        java.util.List<RuntimeSecurity.Detection> events = new java.util.ArrayList<>();
        RuntimeSecurity.subscribeRisk(events::add);
        try {
            RuntimeSecurity.observedSignals(1 | 4 | (1 << 8) | (1 << 11));
            assertEquals(2, events.size());
            assertEquals("android.native_tracer", events.get(0).signal);
            assertEquals("debugger", events.get(0).code);
            assertEquals("android.frida_port", events.get(1).signal);
            assertEquals("low", events.get(1).confidence);
            assertEquals(false, RuntimeSecurity.shouldReject(4 | (1 << 11), true));
            events.clear();
            RuntimeSecurity.observedSignals(1 | 2 | 4);
            assertEquals(3, events.size());
            assertEquals("runtime.aggregate", events.get(0).signal);
        } finally { RuntimeSecurity.subscribeRisk(null); }
    }

    @Test
    public void 安全环境允许继续启动() {
        RuntimeSecurity.enforceSafe(false);
    }

    @Test
    public void 不安全环境拒绝继续启动() {
        try {
            RuntimeSecurity.enforceSafe(true);
            fail("不安全环境未被拒绝");
        } catch (SecurityException error) {
            assertEquals("S01", error.getMessage());
        }
    }

    @Test
    public void 兼容模式忽略Root但始终拒绝反调试() {
        assertEquals(false, RuntimeSecurity.shouldReject(2, false));
        assertEquals(true, RuntimeSecurity.shouldReject(1, false));
    }

    @Test
    public void 阻断状态在所有策略下拒绝且低置信信号仅记录() {
        assertEquals(true, RuntimeSecurity.shouldReject(8, false));
        assertEquals(true, RuntimeSecurity.shouldReject(8, true));
        assertEquals(false, RuntimeSecurity.shouldReject(4, true));
    }

    @Test
    public void 严格模式拒绝Root信号() {
        assertEquals(true, RuntimeSecurity.shouldReject(2, true));
    }
}
