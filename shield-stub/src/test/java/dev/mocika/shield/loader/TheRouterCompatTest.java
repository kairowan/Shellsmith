package dev.mocika.shield.loader;

import org.junit.Test;

import java.lang.reflect.Method;

import static org.junit.Assert.assertEquals;

public class TheRouterCompatTest {

    @Test
    public void 选择单参数静态Autowired注入方法() throws Exception {
        Method method = TheRouterCompat.findAutowiredMethod(GeneratedAutowired.class);
        assertEquals("inject", method.getName());
    }

    public static final class GeneratedAutowired {
        public static void inject(Object target) {}
        public static void ignored(Object first, Object second) {}
        public void instance(Object target) {}
    }
}
