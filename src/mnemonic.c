#include "mnemonic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include "include/utils/sha512_256.h"
#include "base2048.h"

#include "vertices_log.h"

WordMap word_map;
WordVector word_vec;

void init_word_vector(WordVector* vec) {
    vec->capacity = 10;
    vec->words = (char**)malloc(vec->capacity * sizeof(char*));
    vec->size = 0;
}

void push_back_word_vector(WordVector* vec, const char* word) {
    if (vec->size >= vec->capacity) {
        vec->capacity *= 2;
        vec->words = (char**)realloc(vec->words, vec->capacity * sizeof(char*));
    }
    vec->words[vec->size++] = strdup(word);
}

void free_word_vector(WordVector* vec) {
    for (int i = 0; i < vec->size; ++i) {
        free(vec->words[i]);
    }
    free(vec->words);
    vec->words = NULL;
    vec->size = 0;
    vec->capacity = 0;
}

void init_word_map(WordMap* map) {
    map->capacity = 2048; // Assuming a maximum of 2048 words
    map->keys = (char**)malloc(map->capacity * sizeof(char*));
    map->values = (int*)malloc(map->capacity * sizeof(int));
    map->size = 0;
}

void insert_word_map(WordMap* map, const char* key, int value) {
    map->keys[map->size] = strdup(key);
    map->values[map->size++] = value;
}

ret_code_t lookup_word_map(WordMap* map, const char* key, int *value) {
    for (int i = 0; i < map->size; ++i) {
        if (strcmp(map->keys[i], key) == 0) {
            *value = map->values[i];
        }
    }
    if(*value == -1) {
        LOG_ERROR("Invalid word: %s\n", key);
        return VTC_ERROR_INVALID_PARAM;
    }
    return VTC_SUCCESS;
}

void free_word_map(WordMap* map) {
    for (int i = 0; i < map->size; ++i) {
        free(map->keys[i]);
    }
    free(map->keys);
    free(map->values);
    map->keys = NULL;
    map->values = NULL;
    map->size = 0;
    map->capacity = 0;
}

void free_uint16_vector(Uint16Vector* vec) {
    free(vec->data);
    vec->data = NULL;
    vec->size = 0;
    vec->capacity = 0;
}

WordMap make_word_map(const char* s) {
    WordMap map;
    init_word_map(&map);

    char* str = strdup(s);
    char* token = strtok(str, " ");
    int i = 0;

    while (token != NULL) {
        insert_word_map(&map, token, i++);
        token = strtok(NULL, " ");
    }
    free(str);

    return map;
}

WordVector make_word_vector(const char* s) {
    WordVector vec;
    init_word_vector(&vec);

    char* str = strdup(s);
    char* token = strtok(str, " ");

    while (token != NULL) {
        push_back_word_vector(&vec, token);
        token = strtok(NULL, " ");
    }
    free(str);

    return vec;
}

 ret_code_t checksum(bytes b, uint16_t* check_value) {
    unsigned char result[32] = {0};
    ret_code_t err_code = VTC_SUCCESS;

    err_code = sha512_256((const unsigned char*)b.data, b.size, result, 32);
    if (err_code != VTC_SUCCESS) {
        LOG_ERROR( "SHA512/256 error\n");
        return VTC_ERROR_INVALID_STATE;
    }

    bytes hash = { result, 32 };
    bytes short_hash = { result, 2 };

    Uint16Vector ints = b2048_encode(&short_hash);
    *check_value = ints.data[0];
    free_uint16_vector(&ints);
    return VTC_SUCCESS;
}

 ret_code_t mnemonic_from_seed(bytes seed, char **mnemonic) {
    Uint16Vector encoded = b2048_encode(&seed);

    size_t mnemonic_len = 0;
    for (size_t i = 0; i < encoded.size; ++i) {
        mnemonic_len += strlen(word_vec.words[encoded.data[i]]) + 1;
    }

    uint16_t checkVal = -1;
    ret_code_t err_code = checksum(seed, &checkVal);
    if(err_code != VTC_SUCCESS) {
        return err_code;
    }

    mnemonic_len += strlen(word_vec.words[checkVal]) + 1;

    *mnemonic = (char*)malloc(mnemonic_len);
    *mnemonic[0] = '\0';

    for (size_t i = 0; i < encoded.size; ++i) {
        strcat(*mnemonic, word_vec.words[encoded.data[i]]);
        strcat(*mnemonic, " ");
    }

    err_code = checksum(seed, &checkVal);
    if(err_code != VTC_SUCCESS) {
        return err_code;
    }

    strcat(*mnemonic, word_vec.words[checkVal]);

    free_uint16_vector(&encoded);

    return VTC_SUCCESS;
}

ret_code_t seed_from_mnemonic(const char* mnemonic, bytes *seed) {
    WordVector words = make_word_vector(mnemonic);
    char* checkword = words.words[words.size - 1];
    words.size--;
    
    if (words.size != 24) {
        LOG_ERROR("Seed from mnemonic Error: %d words\n", words.size + 1);
        return VTC_ERROR_INTERNAL;
    }

    int checkVal = -1;
    ret_code_t err_code = lookup_word_map(&word_map, checkword, &checkVal);

    if(err_code != VTC_SUCCESS) {
        return err_code;
    }

    seed->data = (unsigned char*)malloc(32 * sizeof(unsigned char));
    seed->size = 0;

    unsigned val = 0;
    int bits = 0;
    for (int i = 0; i < words.size; ++i) {
        int wordVal = -1;
        err_code = lookup_word_map(&word_map, words.words[i], &wordVal);
        if(err_code != VTC_SUCCESS) {
            return err_code;
        }

        val |= wordVal << bits;
        bits += 11;
        while (bits >= 8) {
            seed->data[seed->size++] = val & 0xFF;
            val >>= 8;
            bits -= 8;
        }
    }

    if (bits > 0) {
        seed->data[seed->size++] = val & 0xFF;
    }

    assert(seed->data[seed->size - 1] == 0); // last byte is supposed to be zero
    seed->size--;

    uint16_t check = -1;
    err_code = checksum(*seed, &check);
    if(err_code != VTC_SUCCESS) {
        return err_code;
    }

    if (check != checkVal) {
        LOG_ERROR("%s != %s\n", word_vec.words[check], word_vec.words[checkVal]);
        return VTC_ERROR_INVALID_STATE;
    }

    free_word_vector(&words);

    return VTC_SUCCESS;
}

const char* english = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact end endless endorse enemy energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose improve impulse inch include income increase index indicate indoor industry infant inflict inform inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure meat mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest net network neutral never news next nice night noble noise nominee noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent park parrot party pass patch path patient patrol pattern pause pave payment peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security seed seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry sort soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo"; // truncated example

void initialize_mnemonic() {
    word_vec = make_word_vector(english);
    word_map = make_word_map(english);
}


