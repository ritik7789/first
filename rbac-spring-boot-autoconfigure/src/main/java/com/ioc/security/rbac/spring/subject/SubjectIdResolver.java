package com.ioc.security.rbac.spring.subject;

import org.springframework.security.core.Authentication;

/**
 * Maps the host application's {@link Authentication} to the subject id used in role assignments.
 * Return {@code null} for anonymous / unauthenticated callers.
 */
@FunctionalInterface
public interface SubjectIdResolver {

    String resolve(Authentication authentication);
}
