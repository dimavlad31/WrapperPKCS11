package atm.project.services;


import org.springframework.stereotype.Service;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;

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
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}