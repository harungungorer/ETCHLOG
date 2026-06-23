package dev.hg.etchlog.server.demo;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** Thrown when the demo tamper endpoint targets a leaf index that does not exist. Maps to 404. */
@ResponseStatus(HttpStatus.NOT_FOUND)
public class DemoLeafNotFoundException extends RuntimeException {

    public DemoLeafNotFoundException(String message) {
        super(message);
    }
}
