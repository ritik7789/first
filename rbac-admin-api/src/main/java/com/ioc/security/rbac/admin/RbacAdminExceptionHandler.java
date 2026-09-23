package com.ioc.security.rbac.admin;

import com.ioc.security.rbac.core.RbacConflictException;
import com.ioc.security.rbac.core.RbacException;
import com.ioc.security.rbac.core.RbacNotFoundException;
import com.ioc.security.rbac.core.RbacValidationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Maps RBAC errors of the admin API to RFC 7807 problem details. Scoped to the admin controller so it never changes
 * the host application's error handling.
 */
@RestControllerAdvice(assignableTypes = RbacAdminController.class)
public class RbacAdminExceptionHandler {

    @ExceptionHandler(RbacException.class)
    public ProblemDetail handle(RbacException ex) {
        HttpStatus status;
        if (ex instanceof RbacNotFoundException) {
            status = HttpStatus.NOT_FOUND;
        } else if (ex instanceof RbacConflictException) {
            status = HttpStatus.CONFLICT;
        } else if (ex instanceof RbacValidationException) {
            status = HttpStatus.BAD_REQUEST;
        } else {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, ex.getMessage());
        problem.setTitle(status.getReasonPhrase());
        return problem;
    }
}
