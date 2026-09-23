package com.ioc.security.rbac.spring.annotation;

import org.springframework.aop.ClassFilter;
import org.springframework.aop.MethodMatcher;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.AopUtils;
import org.springframework.aop.support.StaticMethodMatcher;
import org.springframework.core.annotation.AnnotatedElementUtils;

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;

/**
 * Matches methods that carry, or whose class (or interface) carries, an RBAC annotation.
 */
public class RbacAnnotationPointcut implements Pointcut {

    private final MethodMatcher methodMatcher = new StaticMethodMatcher() {
        @Override
        public boolean matches(Method method, Class<?> targetClass) {
            if (method.getDeclaringClass() == Object.class) {
                return false;
            }
            return annotated(method) || annotated(targetClass)
                    || annotated(AopUtils.getMostSpecificMethod(method, targetClass));
        }
    };

    @Override
    public ClassFilter getClassFilter() {
        return ClassFilter.TRUE;
    }

    @Override
    public MethodMatcher getMethodMatcher() {
        return methodMatcher;
    }

    private static boolean annotated(AnnotatedElement element) {
        return AnnotatedElementUtils.hasAnnotation(element, RequiresPermission.class)
                || AnnotatedElementUtils.hasAnnotation(element, RequiresRole.class);
    }
}
