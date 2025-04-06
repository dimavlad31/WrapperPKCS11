package org.example.services;

import org.springframework.stereotype.Service;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

@Service
public class SignService {
    public byte[] generateRandomHash() {
        byte[] hash = new byte[32];
        new SecureRandom().nextBytes(hash);
        return hash;
    }

    public void writeToFile(String filename, byte[] data, int length) {
        try (FileOutputStream fileOutputStream = new FileOutputStream(filename, false)) {
            fileOutputStream.write(data, 0, length);
            fileOutputStream.flush();  // Asigură scrierea efectivă în fișier
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
