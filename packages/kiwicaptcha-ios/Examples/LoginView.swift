// The four-setting quickstart: endpoint, sitekey, scope and the
// verified-token callback, with the token handed to the form.
import SwiftUI
import KiwiCaptcha

struct LoginView: View {
    @State private var token: String = ""
    @State private var failure: String?

    var body: some View {
        Form {
            Section("Sign in") {
                TextField("Email", text: .constant(""))
                SecureField("Password", text: .constant(""))
            }
            Section {
                KiwiCaptchaView(
                    endpoint: URL(string: "https://api.example.com/api/kcaptcha/challenge")!,
                    scope: "login",
                    sitekey: nil,
                    onVerify: { token in
                        self.token = token
                        self.failure = nil
                    },
                    onError: { message in
                        self.failure = message
                    },
                    onExpire: {
                        self.token = ""
                    })
            }
            if let failure {
                Text(failure).foregroundColor(.red)
            }
            Button("Submit") {
                // Submit the form with token in the kiwi__token field.
            }
        }
    }
}
