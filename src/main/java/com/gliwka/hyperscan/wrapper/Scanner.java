package com.gliwka.hyperscan.wrapper;

import com.gliwka.hyperscan.jni.hs_database_t;
import com.gliwka.hyperscan.jni.hs_scratch_t;
import com.gliwka.hyperscan.jni.match_event_handler;
import org.bytedeco.javacpp.BytePointer;
import org.bytedeco.javacpp.Pointer;
import org.bytedeco.javacpp.SizeTPointer;

import java.io.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static com.gliwka.hyperscan.jni.hyperscan.*;
import static java.util.Collections.emptyList;

/**
 * Scanner, can be used with databases to scan for expressions in input string
 * In case of multithreaded scanning, you need one scanner instance per CPU thread.
 *
 * Scanner references native resources. It is paramount to close it after use.
 * There can only be 256 non-closed scanner instances.
 */
public class Scanner implements Closeable {
    private static AtomicInteger count = new AtomicInteger();;

    public Scanner() {
        // The function pointer for the callback match_event_handler allocates native resources.
        // javacpp limits the number of function pointer instances to 10.
        // The limit has been increased to 256 to match the thread count in modern server CPUs
        // An alternative would be to have a single callback and to use the context pointer to identify
        // the right scanner. I've decided against it to keep this implementation simple and to not have
        // to manage references between context pointers and scanner instances

        if(count.get() >= 256) {
            throw new RuntimeException("There can only be 256 non-closed Scanner instances. Create them once per thread!");
        }

        count.incrementAndGet();
    }


    private static class NativeScratch extends hs_scratch_t {
        private NativeScratch() {
            super();
            this.deallocator(() -> hs_free_scratch(this));
        }
    }

    private NativeScratch scratch = new NativeScratch();

    /**
     * Check if the hardware platform is supported
     * @return true if supported, otherwise false
     */
    public static boolean getIsValidPlatform() {
        return hs_valid_platform() == 0;
    }


    /**
     * Get the version information for the underlying hyperscan library
     * @return version string
     */
    public static String getVersion() {
        return hs_version().getString();
    }

    /**
     * Get the scratch space size in bytes
     * @return count of bytes
     */
    public long getSize() {
        if(scratch == null) {
            throw new IllegalStateException("Scratch space has alredy been deallocated");
        }

        try(SizeTPointer size = new SizeTPointer(1)) {
            hs_scratch_size(scratch, size);
            return size.get();
        }
    }

    /**
     * Allocate a scratch space.  Must be called at least once with each
     * database that will be used before scan is called.
     * @param db Database containing expressions to use for matching
     */
    public void allocScratch(final Database db) {
        if(scratch == null) {
            throw new IllegalStateException("Scratch space has already been deallocated");
        }

        hs_database_t dbPointer = db.getDatabase();
        int hsError = hs_alloc_scratch(dbPointer, scratch);

        if(hsError != 0) {
            throw HyperscanException.hsErrorToException(hsError);
        }
    }

    private final LinkedList<long[]> matchedIds = new LinkedList<>();

    private final match_event_handler matchHandler = new match_event_handler() {
        public int call(int id, long from, long to, int flags, Pointer context) {
            long[] tuple = {id, from, to};
            matchedIds.add(tuple);
            return 0;
        }
    };

    /**
     * scan for a match in a string using a compiled expression database
     * Can only be executed one at a time on a per instance basis
     * @param db Database containing expressions to use for matching
     * @param input String to match against
     * @return List of Matches
     */
    public List<Match> scan(final Database db, final String input) {
        if(scratch == null) {
            throw new IllegalStateException("Scratch space has already been deallocated");
        }

        hs_database_t database = db.getDatabase();

        final byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        final BytePointer bytePointer = new BytePointer(ByteBuffer.wrap(bytes));

        matchedIds.clear();
        int hsError = hs_scan(database, bytePointer, bytes.length, 0, scratch, matchHandler, null);

        if(hsError != 0) {
            throw HyperscanException.hsErrorToException(hsError);
        }

        if(matchedIds.isEmpty()) {
            return emptyList();
        }

        //if string length == byte length, all characters are 1 byte wide -> ASCII, no position mapping necessary
        if(bytes.length == input.length()) {
            return processMatches(input, bytes, db, position -> position);
        }
        else {
            final int[] byteToStringPosition = Utf8.byteToStringPositionMap(input, bytes.length);
            return processMatches(input, bytes, db, bytePosition -> byteToStringPosition[bytePosition]);
        }
    }

    private List<Match> processMatches(String input, byte[] bytes, Database db, Function<Integer, Integer> position) {
        final LinkedList<Match> matches = new LinkedList<>();

        matchedIds.forEach( tuple -> {
            int id = (int)tuple[0];
            long from = tuple[1];
            long to = tuple[2] < 1 ? 1 : tuple[2];
            String match = "";
            Expression matchingExpression = db.getExpression(id);

            int startIndex = position.apply((int)from);
            int endIndex = position.apply((int)to - 1);

            if(matchingExpression.getFlags().contains(ExpressionFlag.SOM_LEFTMOST)) {
                match = input.substring(startIndex, endIndex + 1);
            }

            if (bytes.length > 0) {
                matches.add(new Match(startIndex, endIndex, match, matchingExpression));
            } else {
                matches.add(new Match(0, 0, match, matchingExpression));
            }
        });

        return matches;
    }

    @Override
    public void close() {
        scratch.close();
        matchHandler.close();
        count.decrementAndGet();
        scratch = null;
    }
}
