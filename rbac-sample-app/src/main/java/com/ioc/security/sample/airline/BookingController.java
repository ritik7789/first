package com.ioc.security.sample.airline;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/bookings")
public class BookingController {

    public record BookingRequest(String flight, String passenger) {
    }

    private final BookingService service;

    public BookingController(BookingService service) {
        this.service = service;
    }

    @GetMapping
    public List<BookingService.Booking> list() {
        return service.list();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public BookingService.Booking create(@RequestBody BookingRequest request) {
        return service.create(request.flight(), request.passenger());
    }

    @DeleteMapping("/{id}")
    public BookingService.Booking cancel(@PathVariable long id) {
        return service.cancel(id);
    }
}
