package com.ioc.security.rbac.spring.annotation;

import com.ioc.security.rbac.spring.AccessDecision;
import com.ioc.security.rbac.spring.Logical;
import com.ioc.security.rbac.spring.RbacService;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ClassUtils;

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enforces {@link RequiresPermission} and {@link RequiresRole} before the annotated method runs.
 */
public class RbacMethodInterceptor implements MethodInterceptor {

    private record Requirement(AccessDecision.Type type, List<String> values, Logical logical) {
    }

    private record Key(Method method, Class<?> targetClass) {
    }

    private final ObjectProvider<RbacService> rbacService;
    private final Map<Key, List<Requirement>> cache = new ConcurrentHashMap<>();

    public RbacMethodInterceptor(ObjectProvider<RbacService> rbacService) {
        this.rbacService = rbacService;
    }

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        Object target = invocation.getThis();
        Class<?> targetClass = target != null ? AopUtils.getTargetClass(target) : invocation.getMethod().getDeclaringClass();
        Method method = invocation.getMethod();
        List<Requirement> requirements = cache.computeIfAbsent(new Key(method, targetClass),
                k -> requirements(k.method(), k.targetClass()));
        if (!requirements.isEmpty()) {
            RbacService service = rbacService.getObject();
            String source = ClassUtils.getShortName(targetClass) + "." + method.getName();
            var authentication = SecurityContextHolder.getContext().getAuthentication();
            for (Requirement requirement : requirements) {
                service.check(authentication, requirement.type(), requirement.values(), requirement.logical(), source);
            }
        }
        return invocation.proceed();
    }

    private static List<Requirement> requirements(Method method, Class<?> targetClass) {
        Method specific = AopUtils.getMostSpecificMethod(method, targetClass);
        List<Requirement> result = new ArrayList<>();
        collect(targetClass, result);
        collect(specific, result);
        if (specific != method) {
            collect(method, result);
        }
        return List.copyOf(result);
    }

    private static void collect(AnnotatedElement element, List<Requirement> into) {
        RequiresPermission permission = AnnotatedElementUtils.findMergedAnnotation(element, RequiresPermission.class);
        if (permission != null) {
            add(into, new Requirement(AccessDecision.Type.PERMISSION, List.of(permission.value()),
                    permission.logical()), element);
        }
        RequiresRole role = AnnotatedElementUtils.findMergedAnnotation(element, RequiresRole.class);
        if (role != null) {
            add(into, new Requirement(AccessDecision.Type.ROLE, List.of(role.value()), role.logical()), element);
        }
    }

    private static void add(List<Requirement> into, Requirement requirement, AnnotatedElement element) {
        if (requirement.values().isEmpty()) {
            throw new IllegalStateException("RBAC annotation on " + element + " must list at least one value");
        }
        if (!into.contains(requirement)) {
            into.add(requirement);
        }
    }
}
