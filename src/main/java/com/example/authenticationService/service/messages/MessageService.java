package com.example.authenticationService.service.messages;

import com.example.authenticationService.messageConstants.ErrorMessage;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Service
public class MessageService {
    private final MessageSource messageSource;

    public MessageService(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    public String getMessage(ErrorMessage errorMessage) {
        return messageSource.getMessage(errorMessage.getKey(), null, Locale.ENGLISH);
    }
}
