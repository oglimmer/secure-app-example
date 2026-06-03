package com.example.securevault.repo;

import com.example.securevault.domain.TagGram;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;

public interface TagGramRepository extends JpaRepository<TagGram, Long> {

    /**
     * Returns the ids of this owner's files whose tags collectively contain
     * <em>all</em> of the given query trigrams. This is the necessary condition
     * for "the file has a tag containing every search term"; it can over-match
     * (trigrams recombine across positions and across tags), so the client
     * re-verifies the real substring after decrypting. Runs entirely on the
     * indexed {@code (owner_id, blindIndex)} column — no plaintext, no full scan.
     */
    @Query("""
            select g.file.id from TagGram g
            where g.owner.id = :ownerId and g.blindIndex in :grams
            group by g.file.id
            having count(distinct g.blindIndex) = :gramCount
            """)
    List<Long> findFileIdsContainingAll(@Param("ownerId") Long ownerId,
                                        @Param("grams") Collection<String> grams,
                                        @Param("gramCount") long gramCount);

    void deleteByFileId(Long fileId);
}
