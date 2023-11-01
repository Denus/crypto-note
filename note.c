#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <gtk/gtk.h>

// The AES key should be exactly 32 bytes (256 bits)
#define AES_KEY_SIZE 32

GtkWidget *text_view;
GtkWidget *key_entry;

void generateRandomKey(unsigned char *key) {
    if (RAND_bytes(key, AES_KEY_SIZE) != 1) {
        fprintf(stderr, "Error generating random key\n");
        exit(1);
    }
}

void encryptAES256(const char *input, size_t input_len, const unsigned char *key, unsigned char *output) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, AES_KEY_SIZE * 8, &aesKey);
    AES_encrypt((const unsigned char *)input, output, &aesKey);
}

void decryptAES256(const unsigned char *input, size_t input_len, const unsigned char *key, char *output) {
    AES_KEY aesKey;
    AES_set_decrypt_key(key, AES_KEY_SIZE * 8, &aesKey);
    AES_decrypt(input, (unsigned char *)output, &aesKey);
}

static void encrypt_decrypt(GtkWidget *widget, gpointer data) {
    const char *note = gtk_text_buffer_get_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view)), NULL);
    size_t note_len = strlen(note);

    unsigned char aesKey[AES_KEY_SIZE];
    generateRandomKey(aesKey);

    gtk_entry_set_text(GTK_ENTRY(key_entry), "Key: <Generated, see terminal>");
    
    unsigned char encryptedNote[256];
    encryptAES256(note, note_len, aesKey, encryptedNote);
    
    char decryptedNote[256];
    decryptAES256(encryptedNote, note_len, aesKey, decryptedNote);
    decryptedNote[note_len] = '\0';
    
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view)), decryptedNote, -1);
}

int main(int argc, char *argv[]) {
    GtkWidget *window;
    GtkWidget *encrypt_button;
    GtkWidget *vbox;
    GtkWidget *hbox;

    gtk_init(&argc, &argv);

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);

    vbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    text_view = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_WORD);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), TRUE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text_view), TRUE);

    key_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(key_entry), "Key: <Generated, see terminal>");
    gtk_widget_set_sensitive(key_entry, FALSE);

    hbox = gtk_hbox_new(FALSE, 0);

    encrypt_button = gtk_button_new_with_label("Encrypt/Decrypt");
    g_signal_connect(encrypt_button, "clicked", G_CALLBACK(encrypt_decrypt), NULL);

    gtk_box_pack_start(GTK_BOX(hbox), key_entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), encrypt_button, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(vbox), text_view, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}
