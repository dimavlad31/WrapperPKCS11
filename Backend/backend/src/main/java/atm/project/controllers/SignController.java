package atm.project.controllers;

import atm.project.models.SignRequest;
import atm.project.services.SignService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/sign")
public class SignController {
    private final SignService signService;

    @Autowired
    public SignController(SignService signService){
        this.signService = signService;
    }

    @GetMapping("/getHash")
    public ResponseEntity<Map<String, Object>> getHash() {
        byte[] hash = signService.generateRandomHash();
        signService.writeToFile("hash.bin", hash, hash.length);

        Map<String, Object> response = new HashMap<>();
        response.put("hash", Base64.getEncoder().encodeToString(hash));
        response.put("length", hash.length);
        signService.writeToFile("hash.bin", hash, 32);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/addSign")
    public void addSign(@RequestBody SignRequest request) {
        byte[] signature = Base64.getDecoder().decode(request.getSignature());
        int length = request.getLength();

        signService.writeToFile("signature.bin", signature, length);
    }
}