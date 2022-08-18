use clap::{crate_authors, crate_name, crate_version, Parser};
use std::{env, process};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

const CRATE_NAME: &str = crate_name!();
const CRATE_VERSION: &str = crate_version!();
const CRATE_AUTHOR: &str = crate_authors!();
const CRATE_DESCRIPTION: &str = "
------------------------ THOR MQTT Proxy Server ---------------------------------------

 ####### #     # ####### ######  
    #    #     # #     # #     # 
    #    #     # #     # #     # 
    #    ####### #     # ######  
    #    #     # #     # #   #   
    #    #     # #     # #    #  
    #    #     # ####### #     # 
                                 
                            (,%(@& ,%(@%@/%&%@*%@,,./,/%                        
                 %%#%#%#@/.&(#/&#..&@.@##,%#@&@.@/#@%%@/#*@%(%&#.               
                &/##@#*@%.,%%#&@@*.%/&%,##%#(,@@&,(%@@@%%(##(&@&%#              
                ,,#//%#/&/&%%,@@.&./@/* *@&( &&%&,/@*%@((%#&%%@@.(              
                .*%&&#%*(&&&**#(@*,/#&#//&&*/%#&#,,##*/&%#*&.&/@#*              
                     ,(% &#((#.*&   ,,*#,,% %,*///%&#/*&#@/%(.                  
                         (%(%.*((%(((*. *%#  #,.#%#.&#%,%#                      
                             *@ &(@&%@&%@,@@&#&(@@*  #/                         
                               /,@#%@%%@&,&@(&##./#*                            
                               #(**%#@&(&(#&#@%*#@.                             
                               #(@*%%&/(@#.#@,&(@#&                             
                               @@ #*&&&&&(*/@%(@, #                             
                               &%#%...@#%#&(@%.@@#.                             
                              /%%& ,.@@@%&&,@&.//#/#                            
                              & .%. #*#./ %%@(&#@%*.                            
                             &, #&(.&, @..*.@@(.&&(*,                           
                            *%#@. .@,@ @@@@%&%&.,@&.,                           
             *#..%*,      @(*(/ @(&#.*%@@@@&&.%&/#*&/#                          
           &%*/&@@@&@@%##@/*@*&#( %&@&#%*,*  &(/.(@%%@#&@@&@@%@%&/**(%.         
          #/&*&&%#,,.....   ..., ./&@&@&%&&@@&@@@*.,,, , ,,(,#/&%(/**/ *        
          #&*.##..*,/.@&@@@#&./(,*#&/ . @@.@&@(#&&%%%#&%#&#@(   %%&%%/&(        
         &.#%*.@#(&&@%*,#&..%#@*&@ %%#%*@, &  &&%@#% ,#(%  &&&&&( *(@ @@        
         (&(.%,,% .%.%#,&.&# &&% (%%,&#/@.(( &&.@##.%.%.%#%.&.*% &(.%@@##       
        (,%%##/@,%%,@@@,@ @# .. (%.%(# *# .(@.&&@. &#. #@ (#%%#%@%  #/,&(       
        *&/.%@@((@/( &@@@  %%%(  %#%&* @&&  @%#((#% .(.#& (@ ,*((.%*%# &*       
        .% .@@#/#&*/#/. .##@#, ,,.&.&@..@@ &%/.,..( *& &@/%(% .,#(%,.//*%       
                        .(@*,(. %&%@@ &# @ %@@ & %#.. %*.@  (%                  
                              /#*#,.,%#  %%@@.,#. (,.                           
                                    @/.@%.(*&.                                  
                                      .**&*    

Powerful TLS termination and MQTT proxy
";

///------------------------ THOR MQTT Proxy Server ---------------------------------------
#[derive(Parser)]
#[clap(name = CRATE_NAME, version = CRATE_VERSION, author = CRATE_AUTHOR, about = CRATE_DESCRIPTION)]
struct Opts {
    /// Sets a custom config file.
    #[cfg(debug_assertions)]
    #[clap(short, default_value = "config.toml")]
    config: String,
    #[cfg(not(debug_assertions))]
    #[clap(short, default_value = "/etc/d.thor/config.toml")]
    config: String,
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    Run(Run),
}

/// Running STT daemon and Deepspeech services
#[derive(Parser)]
struct Run {}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let opts: Opts = Opts::parse();

    env::set_var("VERSION", CRATE_VERSION);

    let config = thor::config::Settings::new(opts.config).unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {}", err);
        process::exit(1);
    });

    let subscriber = FmtSubscriber::builder()
        .with_max_level(match config.logging_level.as_str() {
            "debug" => Level::DEBUG,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            "info" => Level::INFO,
            _ => Level::TRACE,
        })
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    match opts.subcmd {
        SubCommand::Run(_) => {
            if let Err(e) = thor::run(config).await {
                eprintln!("Application error: {:?}", e);

                process::exit(1);
            }
        }
    }

    println!("THOR Server is shutting down...");
    process::exit(0);
}
