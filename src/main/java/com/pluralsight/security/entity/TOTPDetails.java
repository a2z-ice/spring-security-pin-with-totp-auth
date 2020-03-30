package com.pluralsight.security.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Document
@RequiredArgsConstructor
@Getter
public class TOTPDetails {
    @Id
    private String id;
    @Indexed(unique = true)
    private final String username;
    private final String secret;
}
