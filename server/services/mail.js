const sgMail = require("@sendgrid/mail");

const template = require("../config/template");
const keys = require("../config/keys");

const { key, sender } = keys.mail;

sgMail.setApiKey(key);

const templateIdWithLink = "d-560c07372ffb487ebe673fd101852992";
const templateIdWithoutLink = "d-bc41d45d3c9d4782bb7f1404b43d3e82";

exports.sendEmail = async (email, type, host, data) => {
  try {
    const message = prepareTemplate(type, host, data);
    const SUBJECT = message.subject;
    const CONTENT = message.text;

    const msg = {
      to: email, // Recipient's email address
      from: sender, // Your email address (must be verified with SendGrid)
      templateId: templateIdWithoutLink, // SendGrid Dynamic Template ID
      dynamic_template_data: {
        emailSubject: `Black Store !! ${SUBJECT}`,
        emailContent: CONTENT,
        twitterUrl: "#",
        instagramUrl: "#",
        facebookUrl: "#",
        whatsappUrl: "#",
        linkedinUrl: "#",
        contactUsEmail: sender,
        unsubscribeUrl: "#",
        unsubscribePreferencesUrl: "#",
      },
    };

    if (message.hasLink) {
      const URL = message.link;
      msg.templateId = templateIdWithLink;
      msg.dynamic_template_data.emailUrl = URL;
    }
    try {
      await sgMail.send(msg);
      console.log("Email sent successfully");
    } catch (error) {
      console.error("Email Error:", error);
      if (error.response) {
        console.error("Main Email Error:", error.response.body);
      }
    }
  } catch (error) {
    console.error("Email Error:", error);
    return error;
  }
};

const prepareTemplate = (type, host, data) => {
  let message;

  switch (type) {
    case "reset":
      message = template.resetEmail(host, data);
      break;

    case "reset-confirmation":
      message = template.confirmResetPasswordEmail();
      break;

    case "signup":
      message = template.signupEmail(data);
      break;

    case "merchant-signup":
      message = template.merchantSignup(host, data);
      break;

    case "merchant-welcome":
      message = template.merchantWelcome(data);
      break;

    case "newsletter-subscription":
      message = template.newsletterSubscriptionEmail();
      break;

    case "contact":
      message = template.contactEmail();
      break;

    case "merchant-application":
      message = template.merchantApplicationEmail();
      break;

    case "merchant-deactivate-account":
      message = template.merchantDeactivateAccount();
      break;

    case "order-confirmation":
      message = template.orderConfirmationEmail(data);
      break;

    default:
      message = {};
  }

  return message;
};

////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

// const sgMail = require("@sendgrid/mail");
// const key = ""
// sgMail.setApiKey(key);
// const msg = {
//   to: "", // Change to your recipient
//   from: "", // Change to your verified sender
//   subject: "Sending with SendGrid is Fun",
//   text: "and easy to do anywhere, even with Node.js",
//   html: "<strong>and easy to do anywhere, even with Node.js</strong>",
// };
// sgMail
//   .send(msg)
//   .then(() => {
//     console.log("Email sent");
//   })
//   .catch((error) => {
//     console.error(error);
//   });
