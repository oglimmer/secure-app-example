package com.example.securevault.file;

import com.example.securevault.auth.AuthInterceptor;
import com.example.securevault.file.dto.FileDtos.FileView;
import com.example.securevault.file.dto.FileDtos.SearchRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/search")
public class SearchController {

    private final FileService fileService;

    public SearchController(FileService fileService) {
        this.fileService = fileService;
    }

    /**
     * Substring ("contains") search. The client breaks each search term into
     * trigrams, computes a blind index for each, and posts the de-duplicated set
     * here; the server returns the (still-encrypted) files holding all of them.
     * The client confirms the real substring after decrypting.
     */
    @PostMapping
    public List<FileView> search(@RequestAttribute(AuthInterceptor.USER_ID_ATTRIBUTE) Long userId,
                                 @Valid @RequestBody SearchRequest req) {
        return fileService.search(userId, req.grams());
    }
}
