use std::env;
use std::fs;
use c_introspect_rs::c_parser::parse_c_file;

fn process_header_file (chapter_num: i32, pathstr: &str) {
    println!("## Chapter {}\n",chapter_num);
    if let Some(itr) = parse_c_file (pathstr) {
        println!("One fine day we ventured into {}",pathstr);
        for cstruct in itr {
            println!(" We came upon struct {}",cstruct.name);
        }
    }
    else {
        println!("Alas, we found nothing in {}",pathstr);
    }
    println!("");
}

fn main() {
    let mut chapter_num : i32 = 0;
    if let Some(arg1) = env::args().nth(1) {
        println!("# Structs of {}\n",arg1);
        if let Ok(itr) = fs::read_dir(arg1) {
            for e in itr {
                if let Ok(entry) = e {
                    if let Ok(m) = entry.metadata() {
                        if m.is_file() {
                            if let Some(s) = entry.file_name().to_str() {
                                if s.ends_with(".h") {
                                    if let Some(pathstr) = entry.path().to_str() {
                                        chapter_num += 1;
                                        process_header_file (chapter_num, pathstr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
