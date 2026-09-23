package com.ioc.security.sample.airline;

import com.ioc.security.rbac.spring.Logical;
import com.ioc.security.rbac.spring.RbacService;
import com.ioc.security.rbac.spring.annotation.RequiresPermission;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bookings: permission checks at the service layer, so every caller (REST, messaging, batch) is protected.
 */
@Service
public class BookingService {

    public record Booking(long id, String flight, String passenger, String airline, boolean cancelled) {
    }

    private final Map<Long, Booking> bookings = new ConcurrentHashMap<>();
    private final AtomicLong ids = new AtomicLong();
    private final RbacService rbac;

    public BookingService(RbacService rbac) {
        this.rbac = rbac;
    }

    @RequiresPermission("booking:read")
    public List<Booking> list() {
        String airline = rbac.currentTenantId().orElse(null);
        return bookings.values().stream().filter(b -> airline == null || airline.equals(b.airline())).toList();
    }

    @RequiresPermission("booking:create")
    public Booking create(String flight, String passenger) {
        long id = ids.incrementAndGet();
        Booking booking = new Booking(id, flight, passenger, rbac.currentTenantId().orElse(null), false);
        bookings.put(id, booking);
        return booking;
    }

    /** Agents may cancel; supervisors may also force-cancel. */
    @RequiresPermission(value = {"booking:cancel", "booking:force-cancel"}, logical = Logical.ANY)
    public Booking cancel(long id) {
        return bookings.computeIfPresent(id, (k, b) -> new Booking(b.id(), b.flight(), b.passenger(), b.airline(), true));
    }
}
