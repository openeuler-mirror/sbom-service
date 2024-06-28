package org.opensourceway.sbom.utils;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

@Component
public class SignatureUtil {
    private static final Logger logger = LoggerFactory.getLogger(SignatureUtil.class);

    public static final String SIGN_SUFFIX = ".asc";

    @Value("${signatrust.client}")
    private String client;

    @Value("${signatrust.client.config}")
    private String clientConfig;

    @Value("${signatrust.key.name}")
    private String keyName;

    public SignFile sign(String filename, byte[] content) {
        try {
            var tmpDirPath = Files.createTempDirectory("signatrust");
            var file = tmpDirPath.resolve(filename);
            Files.write(file, content);
            return sign(file.toString());
        } catch (IOException e) {
            logger.warn("Failed to sign <{}>.", filename, e);
            return null;
        }
    }

    public SignFile sign(String file) {
        if (Files.notExists(Path.of(file))) {
            logger.warn("Try to sign <{}>, but file does not exist.", file);
            return null;
        }

        if (StringUtils.isEmpty(client) || Files.notExists(Path.of(client))) {
            logger.warn("Try to sign <{}>, but signatrust client <{}> does not exist.", file, client);
            return null;
        }

        if (StringUtils.isEmpty(clientConfig) || Files.notExists(Path.of(clientConfig))) {
            logger.warn("Try to sign <{}>, but signatrust client config <{}> does not exist.", file, clientConfig);
            return null;
        }

        var builder = new ProcessBuilder();
        builder.inheritIO().command(client, "--config", clientConfig, "add", "--file-type", "generic",
                "--key-type", "pgp", "--key-name", keyName, "--detached", file);
        try {
            var process = builder.start();
            var exit = process.waitFor(5, TimeUnit.SECONDS);
            if (!exit) {
                process.destroy();
                logger.warn("Timeout when signs file <{}>", file);
                return null;
            }

            var exitValue = process.exitValue();
            var signFile = Path.of("%s%s".formatted(file, SIGN_SUFFIX));
            if (exitValue == 0 && Files.exists(signFile)) {
                logger.info("Successfully signed file <{}>", file);
                return new SignFile(signFile.getFileName().toString(), Files.readAllBytes(signFile));
            } else {
                logger.warn("Failed to signed file <{}>", file);
                return null;
            }
        } catch (IOException | InterruptedException e) {
            logger.warn("Unknown exception occurs when signs file <{}>", file, e);
            return null;
        }
    }

    public static class SignFile {
        private String filename;

        private byte[] content;

        public SignFile(String filename, byte[] content) {
            this.filename = filename;
            this.content = content;
        }

        public String getFilename() {
            return filename;
        }

        public void setFilename(String filename) {
            this.filename = filename;
        }

        public byte[] getContent() {
            return content;
        }

        public void setContent(byte[] content) {
            this.content = content;
        }
    }
}
