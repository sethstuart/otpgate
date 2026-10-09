package dev.rei.otpgate;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.bukkit.Material;
import org.bukkit.NamespacedKey;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.MapMeta;
import org.bukkit.map.MapCanvas;
import org.bukkit.map.MapRenderer;
import org.bukkit.map.MapView;
import org.bukkit.persistence.PersistentDataType;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.Location;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.entity.FoodLevelChangeEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerItemConsumeEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerSwapHandItemsEvent;
import org.bukkit.plugin.java.JavaPlugin;

/**
 * OtpGate: authenticator-app login with no password (Seth, 2026-10-08, after the FishNet attack on the
 * offline-mode server). Every player must enter a 6-digit TOTP code before they can move, chat, use commands
 * or touch anything. Enrolment needs a one-time setup code that only the console can issue, so a stolen name
 * is useless twice over: no setup code to enrol, no phone to log in.
 *
 *   player:  /otp <code>                 log in
 *            /otp setup <setupcode>      first time: shows the key to add to an authenticator app
 *            /otp confirm <code>         finishes enrolment (and logs in)
 *   console: otp issue <name>            new one-time setup code (wipes any existing key)
 *            otp setkey <name> <base32>  set a key directly (bots)
 *            otp remove <name> | otp list
 */
public final class OtpGate extends JavaPlugin implements Listener {
    private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final long SESSION_MS = 10 * 60 * 1000L;   // same IP within 10 min: no code needed
    private static final int KICK_AFTER_S = 120;          // log in with a code
    private static final int SETUP_KICK_S = 600;          // first-time setup: time to add the key to an app
    static final String ISSUER = "node07";
    private final SecureRandom rng = new SecureRandom();
    private final Set<UUID> locked = new HashSet<>();
    private final Map<UUID, Location> anchor = new HashMap<>();
    private final Map<UUID, Integer> fails = new HashMap<>();
    private final Map<UUID, Object[]> stash = new HashMap<>();   // {slot, the item the QR map replaced}
    private NamespacedKey qrTag;
    private File file;
    private YamlConfiguration db;

    @Override
    public void onEnable() {
        getDataFolder().mkdirs();
        qrTag = new NamespacedKey(this, "otpqr");
        file = new File(getDataFolder(), "players.yml");
        db = YamlConfiguration.loadConfiguration(file);
        db.options().pathSeparator('/');   // Bedrock names start with '.', the default separator
        getServer().getPluginManager().registerEvents(this, this);
        for (Player p : Bukkit.getOnlinePlayers()) lock(p);   // a reload never leaves anyone unlocked
    }

    private void save() {
        try { db.save(file); } catch (IOException e) { getLogger().severe("save failed: " + e); }
    }

    private static String key(String name) { return "players/" + name.toLowerCase(Locale.ROOT); }

    // ------------------------------------------------------------------------------------------- TOTP
    static String newSecret(SecureRandom r) {
        byte[] b = new byte[20];
        r.nextBytes(b);
        StringBuilder s = new StringBuilder();
        int buf = 0, bits = 0;
        for (byte x : b) {
            buf = (buf << 8) | (x & 0xff); bits += 8;
            while (bits >= 5) { s.append(B32.charAt((buf >> (bits - 5)) & 31)); bits -= 5; }
        }
        if (bits > 0) s.append(B32.charAt((buf << (5 - bits)) & 31));
        return s.toString();
    }

    static byte[] b32decode(String s) {
        s = s.replace(" ", "").replace("=", "").toUpperCase(Locale.ROOT);
        ByteBuffer out = ByteBuffer.allocate(s.length() * 5 / 8);
        int buf = 0, bits = 0;
        for (char c : s.toCharArray()) {
            int v = B32.indexOf(c);
            if (v < 0) throw new IllegalArgumentException("not base32");
            buf = (buf << 5) | v; bits += 5;
            if (bits >= 8) { out.put((byte) (buf >> (bits - 8))); bits -= 8; }
        }
        return out.array();
    }

    static int totp(byte[] secret, long step) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(secret, "HmacSHA1"));
        byte[] h = mac.doFinal(ByteBuffer.allocate(8).putLong(step).array());
        int o = h[h.length - 1] & 0xf;
        int bin = ((h[o] & 0x7f) << 24) | ((h[o + 1] & 0xff) << 16) | ((h[o + 2] & 0xff) << 8) | (h[o + 3] & 0xff);
        return bin % 1_000_000;
    }

    /** The code is right for this 30 s step or one either side; a step may only be used once (no replay). */
    private boolean check(String name, String secret, String code) {
        if (!code.matches("\\d{6}")) return false;
        long now = System.currentTimeMillis() / 30000L;
        long last = db.getLong(key(name) + "/lastStep", 0);
        try {
            byte[] k = b32decode(secret);
            for (long s = now - 1; s <= now + 1; s++) {
                if (s > last && totp(k, s) == Integer.parseInt(code)) {
                    db.set(key(name) + "/lastStep", s);
                    return true;
                }
            }
        } catch (Exception e) { getLogger().warning("totp check failed for " + name + ": " + e); }
        return false;
    }

    static String sha256(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder h = new StringBuilder();
            for (byte b : d) h.append(String.format("%02x", b));
            return h.toString();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    // ------------------------------------------------------------------------------------------- lock state
    private void lock(Player p) {
        locked.add(p.getUniqueId());
        anchor.put(p.getUniqueId(), p.getLocation());
        p.setInvulnerable(true);
    }

    private void unlock(Player p) {
        locked.remove(p.getUniqueId());
        anchor.remove(p.getUniqueId());
        fails.remove(p.getUniqueId());
        p.setInvulnerable(false);
        String k = key(p.getName());
        db.set(k + "/lastIp", ip(p));
        db.set(k + "/lastAuth", System.currentTimeMillis());
        save();
        p.sendMessage(ChatColor.GREEN + "Logged in.");
        getLogger().info(p.getName() + " logged in");
    }

    private static String ip(Player p) {
        return p.getAddress() == null ? "" : p.getAddress().getAddress().getHostAddress();
    }

    private void prompt(Player p) {
        String k = key(p.getName());
        if (db.getBoolean(k + "/confirmed")) {
            p.sendMessage(ChatColor.YELLOW + "Enter your authenticator code: " + ChatColor.WHITE + "/otp <6-digit code>");
        } else if (db.getString(k + "/pending") != null) {
            p.sendMessage(ChatColor.YELLOW + "Finish setup: " + ChatColor.WHITE + "/otp confirm <6-digit code>");
        } else {
            p.sendMessage(ChatColor.YELLOW + "This account needs setup. Enter the setup code you were given: "
                    + ChatColor.WHITE + "/otp setup <code>");
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onJoin(PlayerJoinEvent e) {
        Player p = e.getPlayer();
        String k = key(p.getName());
        boolean fresh = db.getBoolean(k + "/confirmed")
                && ip(p).equals(db.getString(k + "/lastIp"))
                && System.currentTimeMillis() - db.getLong(k + "/lastAuth", 0) < SESSION_MS;
        if (fresh) {
            p.sendMessage(ChatColor.GREEN + "Welcome back (session).");
            return;
        }
        lock(p);
        String pending = db.getString(k + "/pending");
        if (pending != null) showSetup(p, pending); else prompt(p);
        UUID id = p.getUniqueId();
        long wait = db.getBoolean(k + "/confirmed") ? KICK_AFTER_S : SETUP_KICK_S;
        Bukkit.getScheduler().runTaskLater(this, () -> {
            Player q = Bukkit.getPlayer(id);
            if (q != null && locked.contains(id)) q.kickPlayer("No authenticator code entered in time.");
        }, wait * 20L);
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent e) {
        removeQr(e.getPlayer());
        locked.remove(e.getPlayer().getUniqueId());
        anchor.remove(e.getPlayer().getUniqueId());
        fails.remove(e.getPlayer().getUniqueId());
    }

    // ------------------------------------------------------------------------------------------- commands
    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] a) {
        if (sender instanceof ConsoleCommandSender) return console(sender, a);
        if (!(sender instanceof Player p)) return true;
        String k = key(p.getName());
        if (a.length == 1 && a[0].matches("\\d{6}")) {
            if (!locked.contains(p.getUniqueId())) { p.sendMessage(ChatColor.GRAY + "Already logged in."); return true; }
            String secret = db.getString(k + "/secret");
            if (secret == null || !db.getBoolean(k + "/confirmed")) { prompt(p); return true; }
            if (check(p.getName(), secret, a[0])) unlock(p); else wrong(p);
            return true;
        }
        if (a.length == 1 && a[0].equalsIgnoreCase("setup") && db.getString(k + "/pending") != null) {
            showSetup(p, db.getString(k + "/pending"));
            return true;
        }
        if (a.length == 2 && a[0].equalsIgnoreCase("setup")) {
            String hash = db.getString(k + "/setupHash");
            if (hash == null || !hash.equals(sha256(a[1].trim().toLowerCase(Locale.ROOT)))) { wrong(p); return true; }
            String secret = newSecret(rng);
            db.set(k + "/pending", secret);
            db.set(k + "/setupHash", null);   // one time
            save();
            showSetup(p, secret);
            getLogger().info(p.getName() + " started OTP setup");
            return true;
        }
        if (a.length == 2 && a[0].equalsIgnoreCase("confirm")) {
            String pending = db.getString(k + "/pending");
            if (pending == null) { prompt(p); return true; }
            if (!check(p.getName(), pending, a[1])) { wrong(p); return true; }
            db.set(k + "/secret", pending);
            db.set(k + "/pending", null);
            db.set(k + "/confirmed", true);
            save();
            removeQr(p);
            p.sendMessage(ChatColor.GREEN + "Authenticator set up. From now on, log in with /otp <code>.");
            if (locked.contains(p.getUniqueId())) unlock(p);
            return true;
        }
        prompt(p);
        return true;
    }

    static String otpauth(String name, String secret) {
        String label = (ISSUER + ":" + name).replace(" ", "%20");
        return "otpauth://totp/" + label + "?secret=" + secret + "&issuer=" + ISSUER
                + "&algorithm=SHA1&digits=6&period=30";
    }

    private void showSetup(Player p, String secret) {
        p.sendMessage(ChatColor.AQUA + "Setup (only you can see this). Scan the QR map in your hand with your "
                + "authenticator app, or enter this key by hand:");
        p.sendMessage(ChatColor.WHITE + "" + ChatColor.BOLD + secret.replaceAll("(.{4})", "$1 ").trim());
        p.sendMessage(ChatColor.GRAY + "Type: time-based (TOTP), SHA1, 6 digits, 30 s. Account: " + p.getName()
                + ", issuer: " + ISSUER + " (optional). You have " + SETUP_KICK_S / 60 + " minutes.");
        p.sendMessage(ChatColor.AQUA + "Then type " + ChatColor.WHITE + "/otp confirm <6-digit code>"
                + ChatColor.AQUA + ". Lost this screen? " + ChatColor.WHITE + "/otp setup");
        giveQr(p, otpauth(p.getName(), secret));
    }

    private void giveQr(Player p, String text) {
        removeQr(p);
        BitMatrix m;
        try {
            m = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, Map.of(EncodeHintType.MARGIN, 2));
        } catch (Exception e) { getLogger().warning("QR encode failed: " + e); return; }
        MapView view = Bukkit.createMap(p.getWorld());
        for (MapRenderer r : view.getRenderers()) view.removeRenderer(r);
        view.setTrackingPosition(false);
        view.setUnlimitedTracking(false);
        final BitMatrix bm = m;
        view.addRenderer(new MapRenderer(false) {
            private boolean drawn;
            @Override public void render(MapView v, MapCanvas c, Player who) {
                if (drawn) return;
                int w = bm.getWidth(), s = Math.max(1, 128 / w), off = (128 - w * s) / 2;
                for (int x = 0; x < 128; x++) for (int y = 0; y < 128; y++) c.setPixelColor(x, y, java.awt.Color.WHITE);
                for (int x = 0; x < w; x++) for (int y = 0; y < w; y++) if (bm.get(x, y))
                    for (int dx = 0; dx < s; dx++) for (int dy = 0; dy < s; dy++)
                        c.setPixelColor(off + x * s + dx, off + y * s + dy, java.awt.Color.BLACK);
                drawn = true;
            }
        });
        ItemStack map = new ItemStack(Material.FILLED_MAP);
        MapMeta meta = (MapMeta) map.getItemMeta();
        meta.setMapView(view);
        meta.setDisplayName(ChatColor.AQUA + "Authenticator QR (" + p.getName() + ")");
        meta.getPersistentDataContainer().set(qrTag, PersistentDataType.BYTE, (byte) 1);
        map.setItemMeta(meta);
        int slot = p.getInventory().getHeldItemSlot();
        stash.put(p.getUniqueId(), new Object[]{slot, p.getInventory().getItem(slot)});
        p.getInventory().setItem(slot, map);
    }

    /** Take every QR map back (it carries the secret) and return the item it replaced. */
    private void removeQr(Player p) {
        var inv = p.getInventory();
        for (int i = 0; i < inv.getSize(); i++) {
            ItemStack it = inv.getItem(i);
            if (it != null && it.hasItemMeta() && it.getItemMeta().getPersistentDataContainer().has(qrTag, PersistentDataType.BYTE)) {
                inv.setItem(i, null);
            }
        }
        Object[] s = stash.remove(p.getUniqueId());
        if (s != null && inv.getItem((int) s[0]) == null) inv.setItem((int) s[0], (ItemStack) s[1]);
    }

    private void wrong(Player p) {
        int n = fails.merge(p.getUniqueId(), 1, Integer::sum);
        getLogger().warning(p.getName() + " (" + ip(p) + ") failed OTP attempt " + n);
        if (n >= 5) { p.kickPlayer("Too many wrong codes."); return; }
        p.sendMessage(ChatColor.RED + "Wrong code.");
    }

    private boolean console(CommandSender s, String[] a) {
        if (a.length == 2 && a[0].equalsIgnoreCase("issue")) {
            String code = newSecret(rng).substring(0, 10).toLowerCase(Locale.ROOT);
            String k = key(a[1]);
            db.set(k, null);
            db.set(k + "/setupHash", sha256(code));
            save();
            s.sendMessage("Setup code for " + a[1] + ": " + code + "  (they type: /otp setup " + code + ")");
            return true;
        }
        if (a.length == 3 && a[0].equalsIgnoreCase("setkey")) {
            b32decode(a[2]);
            String k = key(a[1]);
            db.set(k, null);
            db.set(k + "/secret", a[2].toUpperCase(Locale.ROOT));
            db.set(k + "/confirmed", true);
            save();
            s.sendMessage("Key set for " + a[1]);
            return true;
        }
        if (a.length == 2 && a[0].equalsIgnoreCase("remove")) {
            db.set(key(a[1]), null);
            save();
            s.sendMessage("Removed " + a[1]);
            return true;
        }
        if (a.length == 1 && a[0].equalsIgnoreCase("list")) {
            var sec = db.getConfigurationSection("players");
            if (sec != null) for (String n : sec.getKeys(false)) {
                s.sendMessage(n + ": " + (sec.getBoolean(n + "/confirmed") ? "set up"
                        : sec.getString(n + "/pending") != null ? "setup started" : "setup code issued"));
            }
            return true;
        }
        s.sendMessage("otp issue <name> | otp setkey <name> <base32> | otp remove <name> | otp list");
        return true;
    }

    // ------------------------------------------------------------------------------------------- the freeze
    private boolean isLocked(Object o) {
        return o instanceof Player p && locked.contains(p.getUniqueId());
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent e) {
        if (!isLocked(e.getPlayer())) return;
        Location to = e.getTo(), from = e.getFrom();
        if (to != null && (to.getX() != from.getX() || to.getY() != from.getY() || to.getZ() != from.getZ())) {
            Location a = anchor.getOrDefault(e.getPlayer().getUniqueId(), from).clone();
            a.setYaw(to.getYaw());
            a.setPitch(to.getPitch());
            e.setTo(a);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onChat(AsyncPlayerChatEvent e) {
        if (isLocked(e.getPlayer())) { e.setCancelled(true); prompt(e.getPlayer()); }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onCommandPre(PlayerCommandPreprocessEvent e) {
        if (!isLocked(e.getPlayer())) return;
        String m = e.getMessage().toLowerCase(Locale.ROOT);
        if (!(m.equals("/otp") || m.startsWith("/otp "))) { e.setCancelled(true); prompt(e.getPlayer()); }
    }

    @EventHandler(priority = EventPriority.LOWEST) public void a(PlayerInteractEvent e) { if (isLocked(e.getPlayer())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.LOWEST) public void b(PlayerInteractEntityEvent e) { if (isLocked(e.getPlayer())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.LOWEST) public void c(BlockBreakEvent e) { if (isLocked(e.getPlayer())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.LOWEST) public void d(BlockPlaceEvent e) { if (isLocked(e.getPlayer())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.LOWEST) public void f(PlayerDropItemEvent e) { if (isLocked(e.getPlayer())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.LOWEST) public void g(EntityPickupItemEvent e) { if (isLocked(e.getEntity())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.LOWEST) public void h(InventoryClickEvent e) { if (isLocked(e.getWhoClicked())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.LOWEST) public void i(InventoryOpenEvent e) { if (isLocked(e.getPlayer())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.LOWEST) public void j(PlayerItemConsumeEvent e) { if (isLocked(e.getPlayer())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.LOWEST) public void k(PlayerSwapHandItemsEvent e) { if (isLocked(e.getPlayer())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.LOWEST) public void l(FoodLevelChangeEvent e) { if (isLocked(e.getEntity())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.LOWEST) public void m(EntityDamageEvent e) { if (isLocked(e.getEntity())) e.setCancelled(true); }
    @EventHandler(priority = EventPriority.LOWEST) public void n(EntityDamageByEntityEvent e) { if (isLocked(e.getDamager())) e.setCancelled(true); }
}
