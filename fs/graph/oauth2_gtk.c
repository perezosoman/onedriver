#ifdef __has_include
#  if __has_include(<webkit2gtk-4.1/webkit2/webkit2.h>)
#    include <webkit2gtk-4.1/webkit2/webkit2.h>
#  elif __has_include(<webkitgtk-4.1/webkit2/webkit2.h>)
#    include <webkitgtk-4.1/webkit2/webkit2.h>
#  else
#    error "Cannot find webkit2/webkit2.h for webkit2gtk-4.1"
#  endif
#else
#  include <webkit2/webkit2.h>
#endif

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Get the host from a URI using GLib's native URI parser (g_uri_parse).
 * Returns a strdup'd string so that Go can free it with C.free().
 */
char *uri_get_host(char *uri) {
    if (!uri || strlen(uri) == 0) {
        return NULL;
    }

    GUri *guri = g_uri_parse(uri, G_URI_FLAGS_NONE, NULL);
    if (!guri) {
        return NULL;
    }

    const char *host = g_uri_get_host(guri);
    char *result = NULL;

    if (host) {
        // strdup instead of g_strdup to ensure compatibility
        // with C.free() on the Go side.
        result = strdup(host);
    }

    g_uri_unref(guri);
    return result;
}

/**
 * Catch redirects once authentication completes.
 */
static void web_view_load_changed(WebKitWebView *web_view, WebKitLoadEvent load_event,
                                  char *auth_redirect_url_ptr) {
    static const char *auth_complete_url = "https://login.live.com/oauth20_desktop.srf";
    const char *url = webkit_web_view_get_uri(web_view);

    if (load_event == WEBKIT_LOAD_REDIRECTED &&
        strncmp(auth_complete_url, url, strlen(auth_complete_url)) == 0) {
        // g_strlcpy guarantees null-termination and prevents overflow.
        g_strlcpy(auth_redirect_url_ptr, url, 2048);

        GtkWidget *parent = gtk_widget_get_parent(GTK_WIDGET(web_view));
        if (parent) {
            gtk_widget_destroy(parent);
        }
    }
}

/**
 * Close the GMainLoop when the window is destroyed.
 */
static void destroy_window(GtkWidget *widget, gpointer data) {
    GMainLoop *loop = (GMainLoop *)data;
    g_main_loop_quit(loop);
}

/**
 * Handle TLS errors during page load. Shows a dialog with details so the user
 * knows what went wrong, then closes the auth window.
 */
static gboolean web_view_load_failed_tls(WebKitWebView *web_view, char *failing_uri,
                                         GTlsCertificate *certificate,
                                         GTlsCertificateFlags errors,
                                         gpointer user_data) {
    GtkWindow *parent = GTK_WINDOW(user_data);

    const char *reason;
    switch (errors) {
    case G_TLS_CERTIFICATE_UNKNOWN_CA:
        reason = "The signing certificate authority is not known.";
        break;
    case G_TLS_CERTIFICATE_BAD_IDENTITY:
        reason = "The certificate does not match the expected identity of the site.";
        break;
    case G_TLS_CERTIFICATE_NOT_ACTIVATED:
        reason = "The certificate's activation time is still in the future.";
        break;
    case G_TLS_CERTIFICATE_EXPIRED:
        reason = "The certificate has expired.";
        break;
    case G_TLS_CERTIFICATE_REVOKED:
        reason = "The certificate has been revoked.";
        break;
    case G_TLS_CERTIFICATE_INSECURE:
        reason = "The certificate's algorithm is considered insecure.";
        break;
    case G_TLS_CERTIFICATE_GENERIC_ERROR:
        reason = "An unknown error occurred validating the certificate.";
        break;
    default:
        reason = "Multiple errors occurred during certificate verification.";
        break;
    }

    g_print("TLS error loading %s: %s\n", failing_uri, reason);

    GtkWidget *dialog = gtk_message_dialog_new(
        parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_ERROR,
        GTK_BUTTONS_CLOSE,
        "Secure connection (TLS) error while contacting Microsoft.\n\n"
        "%s\n\nURL: %s\n\n"
        "Check your system date/time and that CA certificates are up to date.",
        reason, failing_uri);

    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    gtk_widget_destroy(GTK_WIDGET(parent));

    return TRUE;
}

/**
 * Open a popup GTK auth window and return the final redirect location.
 */
char *webkit_auth_window(char *auth_url, char *account_name) {
    gtk_init(NULL, NULL);

    GtkWidget *auth_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

    if (account_name && strlen(account_name) > 0) {
        char title[512];
        snprintf(title, sizeof(title), "onedriver (%s)", account_name);
        gtk_window_set_title(GTK_WINDOW(auth_window), title);
        gtk_window_set_default_size(GTK_WINDOW(auth_window), 525, 600);
    } else {
        gtk_window_set_title(GTK_WINDOW(auth_window), "onedriver");
        gtk_window_set_default_size(GTK_WINDOW(auth_window), 450, 600);
    }

    // create browser and add to gtk window
    WebKitWebView *web_view = WEBKIT_WEB_VIEW(webkit_web_view_new());
    gtk_container_add(GTK_CONTAINER(auth_window), GTK_WIDGET(web_view));
    webkit_web_view_load_uri(web_view, auth_url);

    char auth_redirect_value[2048];
    auth_redirect_value[0] = '\0';

    g_signal_connect(web_view, "load-changed", G_CALLBACK(web_view_load_changed),
                     auth_redirect_value);
    g_signal_connect(web_view, "load-failed-with-tls-errors",
                     G_CALLBACK(web_view_load_failed_tls), auth_window);

    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    g_signal_connect(auth_window, "destroy", G_CALLBACK(destroy_window), loop);

    // show window and grab focus
    gtk_widget_grab_focus(GTK_WIDGET(web_view));
    gtk_widget_show_all(auth_window);

    // block until the window is destroyed
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    return strdup(auth_redirect_value);
}
