use windows_accesstoken::information::TokenElevation;
use windows_accesstoken::AccessToken;
use windows_accesstoken::TokenAccessLevel;
use windows_accesstoken::{
    information::{Groups, LinkedToken},
    security::{GroupSidAttributes, SecurityIdentifier, WellKnownSid},
};
fn main() -> Result<(), std::io::Error> {
    let token = AccessToken::open_process(TokenAccessLevel::Query)?;

    if is_admin_token(&token)? {
        println!("You are an admin");
        return Ok(());
    }

    if token.token_information::<TokenElevation>()? == Some(TokenElevation::Limited) {
        let token = token.token_information::<LinkedToken>()?;

        if let Some(token) = token {
            if is_admin_token(&token)? {
                println!("You are an admin");
                return Ok(());
            }
        }
    }

    println!("You are not an admin");
    Ok(())
}

fn is_admin_token(token: &AccessToken) -> Result<bool, std::io::Error> {
    let admin_sid = SecurityIdentifier::from_known(WellKnownSid::WinBuiltinAdministratorsSid)?;

    if let Some(groups) = token.token_information::<Groups>()? {
        for group in groups {
            if group.0 == admin_sid && group.1.contains(GroupSidAttributes::SE_GROUP_ENABLED) {
                return Ok(true);
            }
        }
    }

    return Ok(false);
}
