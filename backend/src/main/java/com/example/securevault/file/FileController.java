package com.example.securevault.file;

import com.example.securevault.auth.AuthInterceptor;
import com.example.securevault.file.dto.FileDtos.FileContent;
import com.example.securevault.file.dto.FileDtos.FileView;
import com.example.securevault.file.dto.FileDtos.UploadRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/files")
public class FileController {

    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Long> upload(@RequestAttribute(AuthInterceptor.USER_ID_ATTRIBUTE) Long userId,
                                    @Valid @RequestBody UploadRequest req) {
        return Map.of("id", fileService.upload(userId, req));
    }

    @GetMapping
    public List<FileView> list(@RequestAttribute(AuthInterceptor.USER_ID_ATTRIBUTE) Long userId) {
        return fileService.listAll(userId);
    }

    @GetMapping("/{id}")
    public FileContent download(@RequestAttribute(AuthInterceptor.USER_ID_ATTRIBUTE) Long userId,
                                @PathVariable Long id) {
        return fileService.download(userId, id);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@RequestAttribute(AuthInterceptor.USER_ID_ATTRIBUTE) Long userId,
                       @PathVariable Long id) {
        fileService.delete(userId, id);
    }
}
