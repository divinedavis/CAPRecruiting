
// ── Coach college cascading dropdowns ────────────────────────────────────────
window.COLLEGE_DATA = {
    "D1": {
        "ACC": ["Boston College","Clemson","Duke","Florida State","Georgia Tech","Louisville","Miami (FL)","NC State","Notre Dame","North Carolina","Pittsburgh","Syracuse","Virginia","Virginia Tech","Wake Forest"],
        "Big Ten": ["Illinois","Indiana","Iowa","Maryland","Michigan","Michigan State","Minnesota","Nebraska","Northwestern","Ohio State","Penn State","Purdue","Rutgers","UCLA","USC","Washington","Wisconsin"],
        "Big 12": ["Arizona","Arizona State","Baylor","BYU","Cincinnati","Colorado","Houston","Iowa State","Kansas","Kansas State","Oklahoma State","TCU","Texas Tech","UCF","Utah","West Virginia"],
        "SEC": ["Alabama","Arkansas","Auburn","Florida","Georgia","Kentucky","LSU","Mississippi State","Missouri","Ole Miss","South Carolina","Tennessee","Texas","Texas A&M","Vanderbilt"],
        "American Athletic": ["Charlotte","East Carolina","FAU","Memphis","Navy","North Texas","Rice","SMU","South Florida","Temple","Tulane","Tulsa","UAB","UTSA"],
        "Conference USA": ["FIU","Jacksonville State","Louisiana Tech","Middle Tennessee","New Mexico State","Sam Houston","UTEP","Western Kentucky"],
        "MAC": ["Akron","Ball State","Bowling Green","Buffalo","Central Michigan","Eastern Michigan","Kent State","Miami (OH)","NIU","Ohio","Toledo","Western Michigan"],
        "Mountain West": ["Air Force","Boise State","Colorado State","Fresno State","Hawaii","Nevada","New Mexico","San Diego State","San Jose State","UNLV","Utah State","Wyoming"],
        "Sun Belt": ["Appalachian State","Arkansas State","Coastal Carolina","Georgia Southern","Georgia State","James Madison","Louisiana","Marshall","Old Dominion","South Alabama","Southern Miss","Texas State","Troy"],
        "CAA": ["Albany","Delaware","Elon","Hampton","Hofstra","Maine","Monmouth","New Hampshire","Rhode Island","Richmond","Stony Brook","Towson","Villanova","William & Mary"],
        "Ivy League": ["Brown","Columbia","Cornell","Dartmouth","Harvard","Pennsylvania","Princeton","Yale"],
        "MEAC": ["Bethune-Cookman","Coppin State","Delaware State","Florida A&M","Howard","Morgan State","Norfolk State","NC A&T","NC Central","South Carolina State"],
        "Missouri Valley": ["Drake","Illinois State","Indiana State","Missouri State","Murray State","North Dakota State","Northern Iowa","South Dakota","South Dakota State","Southern Illinois","Youngstown State"],
        "NEC": ["Bryant","Central Connecticut","Duquesne","FDU","Long Island","Merrimack","Sacred Heart","Saint Francis","Wagner"],
        "Ohio Valley": ["Austin Peay","Eastern Illinois","Eastern Kentucky","Jacksonville State","Lindenwood","SE Missouri State","Tennessee State","Tennessee Tech","UT Martin"],
        "Patriot League": ["Army","Bucknell","Colgate","Fordham","Georgetown","Holy Cross","Lafayette","Lehigh"],
        "SOCON": ["Chattanooga","ETSU","Furman","Mercer","Samford","The Citadel","VMI","Western Carolina","Wofford"],
        "Southland": ["Abilene Christian","Houston Christian","Incarnate Word","Lamar","McNeese","Nicholls","Northwestern State","SE Louisiana","Tarleton","Texas A&M Commerce"],
        "SWAC": ["Alabama A&M","Alabama State","Alcorn State","Arkansas-Pine Bluff","Florida A&M","Grambling","Jackson State","Mississippi Valley State","Prairie View A&M","Southern","Texas Southern"],
        "WAC": ["Abilene Christian","Cal Baptist","Grand Canyon","New Mexico State","Sam Houston","Seattle","Tarleton","Utah Tech"],
        "FBS Independents": ["Army","Liberty","Massachusetts","Notre Dame","UConn"]
    },
    "D2": {
        "CIAA": ["Bowie State","Elizabeth City State","Fayetteville State","Johnson C. Smith","Livingstone","Shaw","Virginia State","Virginia Union","Winston-Salem State"],
        "GLIAC": ["Ashland","Davenport","Ferris State","Grand Valley State","Hillsdale","Michigan Tech","Northern Michigan","Northwood","Saginaw Valley","Wayne State (MI)"],
        "GSC": ["Christian Brothers","Delta State","Lane","Shorter","Union (TN)","West Alabama","West Florida","West Georgia"],
        "Lone Star": ["Angelo State","Eastern New Mexico","Midwestern State","UTPB","West Texas A&M"],
        "MIAA": ["Augustana (SD)","Bemidji State","Concordia-St. Paul","Minnesota Duluth","Minnesota State","MSU Moorhead","Northern State","St. Cloud State","SW Minnesota State","Wayne State (NE)","Winona State"],
        "NE10": ["Bentley","Franklin Pierce","Merrimack","New Haven","Post","Saint Anselm","Saint Michael's","Southern Connecticut","Stonehill"],
        "PSAC": ["Bloomsburg","California (PA)","Cheney","Clarion","East Stroudsburg","Edinboro","Indiana (PA)","Kutztown","Lock Haven","Mansfield","Millersville","Shippensburg","Slippery Rock","West Chester"],
        "RMAC": ["Adams State","Black Hills State","Colorado Mesa","Colorado Mines","CSU Pueblo","Fort Lewis","New Mexico Highlands","South Dakota Mines","Western Colorado"],
        "SAC": ["Carson-Newman","Catawba","Emory & Henry","Lenoir-Rhyne","Mars Hill","Newberry","Tusculum","Wingate"],
        "SWAC D2": ["Fort Valley State","Miles","Stillman","Tuskegee"]
    },
    "D3": {
        "CCIW": ["Augustana (IL)","Carroll","Carthage","Elmhurst","Illinois Wesleyan","Millikin","North Central","North Park","Wheaton (IL)"],
        "Liberty League": ["Clarkson","Hobart","Ithaca","RPI","Rochester","Skidmore","St. Lawrence","Union (NY)","William Smith"],
        "MAC (D3)": ["Allegheny","Albion","Adrian","Alma","Defiance","Hiram","Kalamazoo","Olivet","Trine"],
        "NESCAC": ["Amherst","Bates","Bowdoin","Colby","Connecticut College","Hamilton","Middlebury","Trinity (CT)","Tufts","Wesleyan","Williams"],
        "New Jersey AC": ["Kean","Montclair State","Rowan","Rutgers-Camden","Rutgers-Newark","TCNJ","William Paterson"],
        "OAC": ["Baldwin Wallace","Capital","Heidelberg","John Carroll","Marietta","Mount Union","Muskingum","Ohio Northern","Otterbein","Wilmington"],
        "PAC": ["Delaware Valley","Eastern","FDU-Florham","Lycoming","Misericordia","Stevenson","Widener","Wilkes"],
        "SAA": ["Berry","Birmingham-Southern","Centre","Hendrix","Millsaps","Oglethorpe","Rhodes","Sewanee","Trinity (TX)"],
        "SCIAC": ["Cal Lutheran","Chapman","Claremont McKenna","La Verne","Occidental","Pomona-Pitzer","Redlands","Whittier"],
        "UAA": ["Brandeis","Carnegie Mellon","Case Western","Chicago","Emory","NYU","Rochester","Washington (MO)"],
        "USA South": ["Christopher Newport","Ferrum","Greensboro","Guilford","LaGrange","Methodist","NC Wesleyan","Shenandoah"],
        "WIAC": ["Eau Claire","La Crosse","Oshkosh","Platteville","River Falls","Stevens Point","Stout","Superior","Whitewater"]
    },
    "NAIA": {
        "NAIA": ["Benedictine (KS)","Briar Cliff","Central Methodist","Concordia (NE)","Doane","Evangel","Friends","Georgetown (KY)","Graceland","Grand View","Kansas Wesleyan","Langston","MidAmerica Nazarene","Midland","Morningside","Northwestern (IA)","Ottawa","Peru State","Saint Francis (IN)","Siena Heights","Southern Oregon","Southwestern (KS)","Sterling","Tabor","Taylor","Valley City State","Waldorf","William Jewell","William Penn"]
    },
    "JUCO": {
        "NJCAA": ["Butler CC","Coffeyville CC","Garden City CC","Iowa Western CC","Iowa Central CC","Jones County JC","Kilgore College","Lackawanna College","Mississippi Gulf Coast CC","Nassau CC","Northwest Mississippi CC","Snow College","Tyler JC"],
        "California CC": ["Allan Hancock","Cerritos","Citrus","College of the Canyons","Diablo Valley","El Camino","Fresno City","Golden West","Grossmont","Modesto","Mt. San Antonio","Pasadena City","Pierce","Riverside City","Sacramento City","San Bernardino Valley","Santa Monica"]
    }
};

