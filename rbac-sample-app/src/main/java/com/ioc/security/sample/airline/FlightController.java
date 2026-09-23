package com.ioc.security.sample.airline;

import com.ioc.security.rbac.spring.annotation.RequiresPermission;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Flight schedule: permission checks on the controller.
 */
@RestController
@RequestMapping("/api/flights")
public class FlightController {

    public record Flight(String number, String from, String to, String status) {
    }

    private final Map<String, Flight> flights = new ConcurrentHashMap<>(Map.of(
            "SK101", new Flight("SK101", "DEL", "BOM", "SCHEDULED"),
            "BJ202", new Flight("BJ202", "BLR", "HYD", "SCHEDULED")));

    @GetMapping
    @RequiresPermission("flight:read")
    public Collection<Flight> list() {
        return flights.values();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission("flight:create")
    public Flight create(@RequestBody Flight flight) {
        flights.put(flight.number(), flight);
        return flight;
    }

    @PostMapping("/{number}/cancel")
    @RequiresPermission("flight:cancel")
    public Flight cancel(@PathVariable String number) {
        return flights.computeIfPresent(number, (k, f) -> new Flight(f.number(), f.from(), f.to(), "CANCELLED"));
    }
}
