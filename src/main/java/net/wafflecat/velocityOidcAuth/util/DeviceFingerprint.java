package net.wafflecat.velocityOidcAuth.util;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.player.PlayerSettings;
import com.velocitypowered.api.proxy.player.SkinParts;
import org.slf4j.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Builds a best-effort fingerprint for the device/connection a player is
 * currently using, so an authenticated session can be tied to it.
 *
 * Minecraft's protocol doesn't expose a real hardware/device identifier, so
 * this is necessarily approximate: it's based on the player's remote IP
 * address, optionally combined with their reported client brand (vanilla,
 * fabric, etc). It raises the bar against someone else casually joining
 * under an already-authenticated username - it is NOT a strong,
 * un-spoofable identity binding (an attacker on the same network/NAT, or
 * spoofing a client brand, isn't stopped by this alone).
 */



public final class DeviceFingerprint {

    private static Logger logger;

    public DeviceFingerprint(Logger logger) {
        DeviceFingerprint.logger = logger;
    }

    public static String compute(Player player)  {
        StringBuilder raw = new StringBuilder();

        // this is like the worst of the worst practices, but I didn't want to spend more time solving this shit
        // because of onServerPreConnect event, sometimes we get here without the client actually sending the player settings...
        // which we use for fingerprinting so, kind of necessary to have them on hand anytime
        while(!player.hasSentPlayerSettings()) {
            logger.debug("Player has not sent the settings yet, waiting");
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }

        String ip = "unknown";
        if (player.getRemoteAddress() != null && player.getRemoteAddress().getAddress() != null) {
            ip = player.getRemoteAddress().getAddress().getHostAddress();
        }
        raw.append("ip=").append(ip);

        String locale = "unknown";
        if (player.getPlayerSettings().getLocale() != null) {
            locale = player.getPlayerSettings().getLocale().toString();
        }
        raw.append("locale=").append(locale);

        String clientBrand = "unknown";
        if (player.getClientBrand() != null) {
            clientBrand = player.getClientBrand();
        }
        raw.append("clientbrand=").append(clientBrand);

        String modInfo = "unknown";
        if (player.getModInfo().isPresent()) {
            modInfo = player.getModInfo().get().getMods().toString();
        }
        raw.append("modinfo=").append(modInfo);

        byte viewDistance = 0;
        if (player.getPlayerSettings().getViewDistance() != 0) {
            viewDistance = player.getPlayerSettings().getViewDistance();
        }
        raw.append("viewdistance=").append(viewDistance);

        int skinParts = 0;
        if (player.getPlayerSettings().getSkinParts().hashCode() != 0) {
            skinParts = player.getPlayerSettings().getSkinParts().hashCode();
        }
        raw.append("skinparts=").append(skinParts);

        logger.info("Fingerprinting info:");
        logger.info("  IP: {}", ip);
        logger.info("  Locale: {}", locale);
        logger.info("  ClientBrand: {}", clientBrand);
        logger.info("  ModInfo: {}", modInfo);
        logger.info("  ViewDistance: {}", viewDistance);
        logger.info("  SkinParts: {}", skinParts);

        return sha256Hex(raw.toString());
    }

    public static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be present on every JDK.
            throw new IllegalStateException(e);
        }
    }
}
