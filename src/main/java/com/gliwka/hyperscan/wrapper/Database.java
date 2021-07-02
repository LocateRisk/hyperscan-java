package com.gliwka.hyperscan.wrapper;

import com.gliwka.hyperscan.jni.hs_compile_error_t;
import com.gliwka.hyperscan.jni.hs_database_t;
import org.bytedeco.javacpp.*;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static com.gliwka.hyperscan.jni.hyperscan.*;
import static java.util.Collections.singletonList;
import static java.util.function.Function.identity;

/**
 * Database containing compiled expressions ready for scanning using the Scanner
 */
public class Database implements Closeable {
    private final Expression[] expressions;
    private final int expressionCount;

    private NativeDatabase database;

    private static class NativeDatabase extends hs_database_t {
        private NativeDatabase() {
            super();
            this.deallocator(() -> hs_free_database(this));
        }
    }

    private Database(NativeDatabase database, List<Expression> expressions) {
        this.database = database;
        this.expressionCount = expressions.size();

        boolean hasIds = expressions.get(0).getId() != null;

        if (hasIds) {
            int maxId = expressions.stream().mapToInt(Expression::getId).max().getAsInt();
            this.expressions = new Expression[maxId + 1];

            expressions.forEach(expression -> this.expressions[expression.getId()] = expression);
        } else {
            this.expressions = expressions.toArray(new Expression[0]);
        }
    }

    private static void handleErrors(int hsError, hs_compile_error_t compileError, List<Expression> expressions) throws CompileErrorException {
        if (hsError == 0) {
            return;
        }

        if (hsError == HS_COMPILER_ERROR) {
            Expression expression = compileError.expression() < 0 ? null : expressions.get(compileError.expression());
            throw new CompileErrorException(compileError.message().getString(), expression);
        } else {
            throw HyperscanException.hsErrorToException(hsError);
        }
    }

    /**
     * compile an expression into a database to use for scanning
     *
     * @param expression Expression to compile
     * @return Compiled database
     */
    public static Database compile(Expression expression) throws CompileErrorException {
        return compile(singletonList(expression));
    }

    /**
     * Compiles an list of expressions into a database to use for scanning
     *
     * @param expressions List of expressions to compile
     * @return Compiled database
     */
    public static Database compile(List<Expression> expressions) throws CompileErrorException {
        final int expressionsSize = expressions.size();

        String[] expressionArray = expressions.stream().map(Expression::getExpression).toArray(String[]::new);
        PointerPointer<BytePointer> nativeExpressions = new PointerPointer<>(expressionsSize);
        nativeExpressions.putString(expressionArray, StandardCharsets.UTF_8);

        int[] flags = new int[expressionsSize];
        int[] ids = new int[expressionsSize];

        boolean expressionWithoutId = expressions.stream().anyMatch(expression -> expression.getId() == null);
        boolean expressionWithId = expressions.stream().anyMatch(expression -> expression.getId() != null);

        if (expressionWithId && expressionWithoutId) {
            throw new IllegalStateException("You can't mix expressions with and without id's in a single database");
        }

        int i = 0;
        final Iterator<Expression> expressionIterator = expressions.iterator();
        while (expressionIterator.hasNext()) {
        	final Expression expression = expressionIterator.next();
        	flags[i] = expression.getFlagBits();

            if (expressionWithId) {
                ids[i] = expression.getId();
            } else {
                ids[i] = i;
            }
        	i++;
        }

        IntPointer nativeFlags = new IntPointer(flags);
        IntPointer nativeIds = new IntPointer(ids);

        try (PointerPointer<hs_compile_error_t> error = new PointerPointer<>(new hs_compile_error_t())) {

            PointerPointer<NativeDatabase> database = new PointerPointer<>(1);
            int hsError = hs_compile_multi(nativeExpressions, nativeFlags, nativeIds, expressionsSize, HS_MODE_BLOCK, null, database, error);

            handleErrors(hsError, error.get(hs_compile_error_t.class), expressions);

            return new Database(database.get(NativeDatabase.class), expressions);
        }
    }

    NativeDatabase getDatabase() {
        return database;
    }


    /**
     * Get the database size in bytes
     *
     * @return count of bytes
     */
    public long getSize() {
        if (database == null) {
            throw new IllegalStateException("Database has already been deallocated");
        }

        try (SizeTPointer size = new SizeTPointer(1)) {
            hs_database_size(database, size);
            return size.get();
        }
    }

    Expression getExpression(int id) {
        return expressions[id];
    }

    int getExpressionCount() {
        return expressionCount;
    }

    @Override
    public void close() {
        database.close();
        database = null;
    }

    /**
     * Saves the expressions and the compiled database to an OutputStream.
     * Expression contexts are not saved.
     * The OutputStream is not closed.
     *
     * @param out stream to write to
     */
    public void save(OutputStream out) throws IOException {
        save(out, out);
    }

    /**
     * Saves the expressions and the compiled database to (possibly) distinct OutputStreams.
     * All of the expressions are saved to expressionsOut before any of the database is saved to databaseOut so it's safe
     * to use the same backing OutputStream for both parameters.
     * Expression contexts are not saved.
     * Neither of the OutputStream is closed.
     *
     * @param expressionsOut stream to write expressions to
     * @param databaseOut    stream to write database to
     */
    public void save(OutputStream expressionsOut, OutputStream databaseOut) throws IOException {
        DataOutputStream expressionsDataOut = new DataOutputStream(expressionsOut);
        // How many expressions will be present. We need this to know when to stop reading.
        expressionsDataOut.writeInt(expressionCount);
        for (Expression expression : expressions) {
            if (expression == null) {
                continue;
            }

            // Expression id
            expressionsDataOut.writeInt(expression.getId() == null ? -1 : expression.getId());
            // Expression pattern
            expressionsDataOut.writeUTF(expression.getExpression());
            // Flag count
            EnumSet<ExpressionFlag> flags = expression.getFlags();
            expressionsDataOut.writeInt(flags.size());
            for (ExpressionFlag flag : flags) {
                // Bitmask for each flag
                expressionsDataOut.writeInt(flag.getBits());
            }
        }
        expressionsDataOut.flush();

        // Serialize the database into a contiguous native memory block
        try (BytePointer bytePointer = new BytePointer(1); SizeTPointer size = new SizeTPointer(1)) {
            int hsError = hs_serialize_database(database, bytePointer, size);

            if (hsError != 0) {
                throw HyperscanException.hsErrorToException(hsError);
            }

            int length = (int) size.get();

            // Write the native memory to the output stream.
            // We could just load all the native memory onto the heap but that would double our memory usage.
            // Instead we copy small blocks at a time
            ByteBuffer buffer = bytePointer.capacity(length).asBuffer();

            DataOutputStream databaseDataOut = new DataOutputStream(databaseOut);
            databaseDataOut.writeInt(length);
            // Neither DataOutputStream nor WritableByteChannel buffer so we can intermix usage.
            Channels.newChannel(databaseDataOut).write(buffer);
            databaseDataOut.flush();
        }
    }

    /**
     * Loads the database saved via {@link #save(OutputStream)}.
     * The saved payload contains platform-specific formatting so it should be loaded on a compatible platform.
     * All Expression contexts will be null.
     *
     * @param in stream to read from
     * @return loaded Database
     */
    public static Database load(InputStream in) throws IOException {
        return load(in, in);
    }


    /**
     * Loads the database saved via {@link #save(OutputStream, OutputStream)}.
     * The saved payload contains platform-specific formatting so it should be loaded on a compatible platform.
     *
     * @param expressionsIn stream to read expressions from
     * @param databaseIn    stream to read database from
     * @return loaded Database
     */
    public static Database load(InputStream expressionsIn, InputStream databaseIn) throws IOException {
        // DataInputStream doesn't buffer so it will only read as much as we ask for.
        // This makes it safe to use even if expressionsIn and databaseIn are the same streams.
        DataInputStream expressionsDataIn = new DataInputStream(expressionsIn);
        int expressionCount = expressionsDataIn.readInt();
        List<Expression> expressions = new ArrayList<>(expressionCount);

        // Setup a lookup map for expression flags
        Map<Integer, ExpressionFlag> bitmaskToFlag = Arrays.stream(ExpressionFlag.values())
                .collect(Collectors.toMap(ExpressionFlag::getBits, identity()));

        for (int i = 0; i < expressionCount; i++) {
            int id = expressionsDataIn.readInt();
            String pattern = expressionsDataIn.readUTF();
            int flagCount = expressionsDataIn.readInt();
            EnumSet<ExpressionFlag> flags = EnumSet.noneOf(ExpressionFlag.class);
            for (int j = 0; j < flagCount; j++) {
                int bitmask = expressionsDataIn.readInt();
                flags.add(bitmaskToFlag.get(bitmask));

            }
            expressions.add(new Expression(pattern, flags, id == -1 ? null : id));
        }

        DataInputStream databaseDataIn = new DataInputStream(databaseIn);
        int length = databaseDataIn.readInt();
        byte[] bytes = new byte[(int) length];

        BytePointer bytePointer = new BytePointer(length);
        databaseDataIn.readFully(bytes);
        bytePointer.put(bytes);

        NativeDatabase database = new NativeDatabase();

        int hsError = hs_deserialize_database(bytePointer, length, database);
        if (hsError != 0) {
            throw HyperscanException.hsErrorToException(hsError);
        }

        return new Database(database, expressions);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Database database = (Database) o;
        return expressionCount == database.expressionCount && Arrays.deepEquals(expressions, database.expressions);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(expressionCount);
        result = 31 * result + Arrays.hashCode(expressions);
        return result;
    }
}
