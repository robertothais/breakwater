#!/usr/bin/env python3
"""
AhnLab Custom SEED Implementation
Based on reverse-engineered code from ASTx
"""

import struct

# Standard SEED S-boxes from RFC 4269
# SS0, SS1, SS2, SS3 - 256 entries each
SS0 = [
    0x2989A1A8,
    0x05858184,
    0x16C6D2D4,
    0x13C3D3D0,
    0x14445054,
    0x1D0D111C,
    0x2C8CA0AC,
    0x25052124,
    0x1D4D515C,
    0x03434340,
    0x18081018,
    0x1E0E121C,
    0x11415150,
    0x3CCCF0FC,
    0x0ACAC2C8,
    0x23436360,
    0x28082028,
    0x04444044,
    0x20002020,
    0x1D8D919C,
    0x20C0E0E0,
    0x22C2E2E0,
    0x08C8C0C8,
    0x17071314,
    0x2585A1A4,
    0x0F8F838C,
    0x03030300,
    0x3B4B7378,
    0x3B8BB3B8,
    0x13031310,
    0x12C2D2D0,
    0x2ECEE2EC,
    0x30407070,
    0x0C8C808C,
    0x3F0F333C,
    0x2888A0A8,
    0x32023230,
    0x1DCDD1DC,
    0x36C6F2F4,
    0x34447074,
    0x2CCCE0EC,
    0x15859194,
    0x0B0B0308,
    0x17475354,
    0x1C4C505C,
    0x1B4B5358,
    0x3D8DB1BC,
    0x01010100,
    0x24042024,
    0x1C0C101C,
    0x33437370,
    0x18889098,
    0x10001010,
    0x0CCCC0CC,
    0x32C2F2F0,
    0x19C9D1D8,
    0x2C0C202C,
    0x27C7E3E4,
    0x32427270,
    0x03838380,
    0x1B8B9398,
    0x11C1D1D0,
    0x06868284,
    0x09C9C1C8,
    0x20406060,
    0x10405050,
    0x2383A3A0,
    0x2BCBE3E8,
    0x0D0D010C,
    0x3686B2B4,
    0x1E8E929C,
    0x0F4F434C,
    0x3787B3B4,
    0x1A4A5258,
    0x06C6C2C4,
    0x38487078,
    0x2686A2A4,
    0x12021210,
    0x2F8FA3AC,
    0x15C5D1D4,
    0x21416160,
    0x03C3C3C0,
    0x3484B0B4,
    0x01414140,
    0x12425250,
    0x3D4D717C,
    0x0D8D818C,
    0x08080008,
    0x1F0F131C,
    0x19899198,
    0x00000000,
    0x19091118,
    0x04040004,
    0x13435350,
    0x37C7F3F4,
    0x21C1E1E0,
    0x3DCDF1FC,
    0x36467274,
    0x2F0F232C,
    0x27072324,
    0x3080B0B0,
    0x0B8B8388,
    0x0E0E020C,
    0x2B8BA3A8,
    0x2282A2A0,
    0x2E4E626C,
    0x13839390,
    0x0D4D414C,
    0x29496168,
    0x3C4C707C,
    0x09090108,
    0x0A0A0208,
    0x3F8FB3BC,
    0x2FCFE3EC,
    0x33C3F3F0,
    0x05C5C1C4,
    0x07878384,
    0x14041014,
    0x3ECEF2FC,
    0x24446064,
    0x1ECED2DC,
    0x2E0E222C,
    0x0B4B4348,
    0x1A0A1218,
    0x06060204,
    0x21012120,
    0x2B4B6368,
    0x26466264,
    0x02020200,
    0x35C5F1F4,
    0x12829290,
    0x0A8A8288,
    0x0C0C000C,
    0x3383B3B0,
    0x3E4E727C,
    0x10C0D0D0,
    0x3A4A7278,
    0x07474344,
    0x16869294,
    0x25C5E1E4,
    0x26062224,
    0x00808080,
    0x2D8DA1AC,
    0x1FCFD3DC,
    0x2181A1A0,
    0x30003030,
    0x37073334,
    0x2E8EA2AC,
    0x36063234,
    0x15051114,
    0x22022220,
    0x38083038,
    0x34C4F0F4,
    0x2787A3A4,
    0x05454144,
    0x0C4C404C,
    0x01818180,
    0x29C9E1E8,
    0x04848084,
    0x17879394,
    0x35053134,
    0x0BCBC3C8,
    0x0ECEC2CC,
    0x3C0C303C,
    0x31417170,
    0x11011110,
    0x07C7C3C4,
    0x09898188,
    0x35457174,
    0x3BCBF3F8,
    0x1ACAD2D8,
    0x38C8F0F8,
    0x14849094,
    0x19495158,
    0x02828280,
    0x04C4C0C4,
    0x3FCFF3FC,
    0x09494148,
    0x39093138,
    0x27476364,
    0x00C0C0C0,
    0x0FCFC3CC,
    0x17C7D3D4,
    0x3888B0B8,
    0x0F0F030C,
    0x0E8E828C,
    0x02424240,
    0x23032320,
    0x11819190,
    0x2C4C606C,
    0x1BCBD3D8,
    0x2484A0A4,
    0x34043034,
    0x31C1F1F0,
    0x08484048,
    0x02C2C2C0,
    0x2F4F636C,
    0x3D0D313C,
    0x2D0D212C,
    0x00404040,
    0x3E8EB2BC,
    0x3E0E323C,
    0x3C8CB0BC,
    0x01C1C1C0,
    0x2A8AA2A8,
    0x3A8AB2B8,
    0x0E4E424C,
    0x15455154,
    0x3B0B3338,
    0x1CCCD0DC,
    0x28486068,
    0x3F4F737C,
    0x1C8C909C,
    0x18C8D0D8,
    0x0A4A4248,
    0x16465254,
    0x37477374,
    0x2080A0A0,
    0x2DCDE1EC,
    0x06464244,
    0x3585B1B4,
    0x2B0B2328,
    0x25456164,
    0x3ACAF2F8,
    0x23C3E3E0,
    0x3989B1B8,
    0x3181B1B0,
    0x1F8F939C,
    0x1E4E525C,
    0x39C9F1F8,
    0x26C6E2E4,
    0x3282B2B0,
    0x31013130,
    0x2ACAE2E8,
    0x2D4D616C,
    0x1F4F535C,
    0x24C4E0E4,
    0x30C0F0F0,
    0x0DCDC1CC,
    0x08888088,
    0x16061214,
    0x3A0A3238,
    0x18485058,
    0x14C4D0D4,
    0x22426260,
    0x29092128,
    0x07070304,
    0x33033330,
    0x28C8E0E8,
    0x1B0B1318,
    0x05050104,
    0x39497178,
    0x10809090,
    0x2A4A6268,
    0x2A0A2228,
    0x1A8A9298,
]

SS1 = [
    0x38380830,
    0xE828C8E0,
    0x2C2D0D21,
    0xA42686A2,
    0xCC0FCFC3,
    0xDC1ECED2,
    0xB03383B3,
    0xB83888B0,
    0xAC2F8FA3,
    0x60204060,
    0x54154551,
    0xC407C7C3,
    0x44044440,
    0x6C2F4F63,
    0x682B4B63,
    0x581B4B53,
    0xC003C3C3,
    0x60224262,
    0x30330333,
    0xB43585B1,
    0x28290921,
    0xA02080A0,
    0xE022C2E2,
    0xA42787A3,
    0xD013C3D3,
    0x90118191,
    0x10110111,
    0x04060602,
    0x1C1C0C10,
    0xBC3C8CB0,
    0x34360632,
    0x480B4B43,
    0xEC2FCFE3,
    0x88088880,
    0x6C2C4C60,
    0xA82888A0,
    0x14170713,
    0xC404C4C0,
    0x14160612,
    0xF434C4F0,
    0xC002C2C2,
    0x44054541,
    0xE021C1E1,
    0xD416C6D2,
    0x3C3F0F33,
    0x3C3D0D31,
    0x8C0E8E82,
    0x98188890,
    0x28280820,
    0x4C0E4E42,
    0xF436C6F2,
    0x3C3E0E32,
    0xA42585A1,
    0xF839C9F1,
    0x0C0D0D01,
    0xDC1FCFD3,
    0xD818C8D0,
    0x282B0B23,
    0x64264662,
    0x783A4A72,
    0x24270723,
    0x2C2F0F23,
    0xF031C1F1,
    0x70324272,
    0x40024242,
    0xD414C4D0,
    0x40014141,
    0xC000C0C0,
    0x70334373,
    0x64274763,
    0xAC2C8CA0,
    0x880B8B83,
    0xF437C7F3,
    0xAC2D8DA1,
    0x80008080,
    0x1C1F0F13,
    0xC80ACAC2,
    0x2C2C0C20,
    0xA82A8AA2,
    0x34340430,
    0xD012C2D2,
    0x080B0B03,
    0xEC2ECEE2,
    0xE829C9E1,
    0x5C1D4D51,
    0x94148490,
    0x18180810,
    0xF838C8F0,
    0x54174753,
    0xAC2E8EA2,
    0x08080800,
    0xC405C5C1,
    0x10130313,
    0xCC0DCDC1,
    0x84068682,
    0xB83989B1,
    0xFC3FCFF3,
    0x7C3D4D71,
    0xC001C1C1,
    0x30310131,
    0xF435C5F1,
    0x880A8A82,
    0x682A4A62,
    0xB03181B1,
    0xD011C1D1,
    0x20200020,
    0xD417C7D3,
    0x00020202,
    0x20220222,
    0x04040400,
    0x68284860,
    0x70314171,
    0x04070703,
    0xD81BCBD3,
    0x9C1D8D91,
    0x98198991,
    0x60214161,
    0xBC3E8EB2,
    0xE426C6E2,
    0x58194951,
    0xDC1DCDD1,
    0x50114151,
    0x90108090,
    0xDC1CCCD0,
    0x981A8A92,
    0xA02383A3,
    0xA82B8BA3,
    0xD010C0D0,
    0x80018181,
    0x0C0F0F03,
    0x44074743,
    0x181A0A12,
    0xE023C3E3,
    0xEC2CCCE0,
    0x8C0D8D81,
    0xBC3F8FB3,
    0x94168692,
    0x783B4B73,
    0x5C1C4C50,
    0xA02282A2,
    0xA02181A1,
    0x60234363,
    0x20230323,
    0x4C0D4D41,
    0xC808C8C0,
    0x9C1E8E92,
    0x9C1C8C90,
    0x383A0A32,
    0x0C0C0C00,
    0x2C2E0E22,
    0xB83A8AB2,
    0x6C2E4E62,
    0x9C1F8F93,
    0x581A4A52,
    0xF032C2F2,
    0x90128292,
    0xF033C3F3,
    0x48094941,
    0x78384870,
    0xCC0CCCC0,
    0x14150511,
    0xF83BCBF3,
    0x70304070,
    0x74354571,
    0x7C3F4F73,
    0x34350531,
    0x10100010,
    0x00030303,
    0x64244460,
    0x6C2D4D61,
    0xC406C6C2,
    0x74344470,
    0xD415C5D1,
    0xB43484B0,
    0xE82ACAE2,
    0x08090901,
    0x74364672,
    0x18190911,
    0xFC3ECEF2,
    0x40004040,
    0x10120212,
    0xE020C0E0,
    0xBC3D8DB1,
    0x04050501,
    0xF83ACAF2,
    0x00010101,
    0xF030C0F0,
    0x282A0A22,
    0x5C1E4E52,
    0xA82989A1,
    0x54164652,
    0x40034343,
    0x84058581,
    0x14140410,
    0x88098981,
    0x981B8B93,
    0xB03080B0,
    0xE425C5E1,
    0x48084840,
    0x78394971,
    0x94178793,
    0xFC3CCCF0,
    0x1C1E0E12,
    0x80028282,
    0x20210121,
    0x8C0C8C80,
    0x181B0B13,
    0x5C1F4F53,
    0x74374773,
    0x54144450,
    0xB03282B2,
    0x1C1D0D11,
    0x24250521,
    0x4C0F4F43,
    0x00000000,
    0x44064642,
    0xEC2DCDE1,
    0x58184850,
    0x50124252,
    0xE82BCBE3,
    0x7C3E4E72,
    0xD81ACAD2,
    0xC809C9C1,
    0xFC3DCDF1,
    0x30300030,
    0x94158591,
    0x64254561,
    0x3C3C0C30,
    0xB43686B2,
    0xE424C4E0,
    0xB83B8BB3,
    0x7C3C4C70,
    0x0C0E0E02,
    0x50104050,
    0x38390931,
    0x24260622,
    0x30320232,
    0x84048480,
    0x68294961,
    0x90138393,
    0x34370733,
    0xE427C7E3,
    0x24240420,
    0xA42484A0,
    0xC80BCBC3,
    0x50134353,
    0x080A0A02,
    0x84078783,
    0xD819C9D1,
    0x4C0C4C40,
    0x80038383,
    0x8C0F8F83,
    0xCC0ECEC2,
    0x383B0B33,
    0x480A4A42,
    0xB43787B3,
]

SS2 = [
    0xA1A82989,
    0x81840585,
    0xD2D416C6,
    0xD3D013C3,
    0x50541444,
    0x111C1D0D,
    0xA0AC2C8C,
    0x21242505,
    0x515C1D4D,
    0x43400343,
    0x10181808,
    0x121C1E0E,
    0x51501141,
    0xF0FC3CCC,
    0xC2C80ACA,
    0x63602343,
    0x20282808,
    0x40440444,
    0x20202000,
    0x919C1D8D,
    0xE0E020C0,
    0xE2E022C2,
    0xC0C808C8,
    0x13141707,
    0xA1A42585,
    0x838C0F8F,
    0x03000303,
    0x73783B4B,
    0xB3B83B8B,
    0x13101303,
    0xD2D012C2,
    0xE2EC2ECE,
    0x70703040,
    0x808C0C8C,
    0x333C3F0F,
    0xA0A82888,
    0x32303202,
    0xD1DC1DCD,
    0xF2F436C6,
    0x70743444,
    0xE0EC2CCC,
    0x91941585,
    0x03080B0B,
    0x53541747,
    0x505C1C4C,
    0x53581B4B,
    0xB1BC3D8D,
    0x01000101,
    0x20242404,
    0x101C1C0C,
    0x73703343,
    0x90981888,
    0x10101000,
    0xC0CC0CCC,
    0xF2F032C2,
    0xD1D819C9,
    0x202C2C0C,
    0xE3E427C7,
    0x72703242,
    0x83800383,
    0x93981B8B,
    0xD1D011C1,
    0x82840686,
    0xC1C809C9,
    0x60602040,
    0x50501040,
    0xA3A02383,
    0xE3E82BCB,
    0x010C0D0D,
    0xB2B43686,
    0x929C1E8E,
    0x434C0F4F,
    0xB3B43787,
    0x52581A4A,
    0xC2C406C6,
    0x70783848,
    0xA2A42686,
    0x12101202,
    0xA3AC2F8F,
    0xD1D415C5,
    0x61602141,
    0xC3C003C3,
    0xB0B43484,
    0x41400141,
    0x52501242,
    0x717C3D4D,
    0x818C0D8D,
    0x00080808,
    0x131C1F0F,
    0x91981989,
    0x00000000,
    0x11181909,
    0x00040404,
    0x53501343,
    0xF3F437C7,
    0xE1E021C1,
    0xF1FC3DCD,
    0x72743646,
    0x232C2F0F,
    0x23242707,
    0xB0B03080,
    0x83880B8B,
    0x020C0E0E,
    0xA3A82B8B,
    0xA2A02282,
    0x626C2E4E,
    0x93901383,
    0x414C0D4D,
    0x61682949,
    0x707C3C4C,
    0x01080909,
    0x02080A0A,
    0xB3BC3F8F,
    0xE3EC2FCF,
    0xF3F033C3,
    0xC1C405C5,
    0x83840787,
    0x10141404,
    0xF2FC3ECE,
    0x60642444,
    0xD2DC1ECE,
    0x222C2E0E,
    0x43480B4B,
    0x12181A0A,
    0x02040606,
    0x21202101,
    0x63682B4B,
    0x62642646,
    0x02000202,
    0xF1F435C5,
    0x92901282,
    0x82880A8A,
    0x000C0C0C,
    0xB3B03383,
    0x727C3E4E,
    0xD0D010C0,
    0x72783A4A,
    0x43440747,
    0x92941686,
    0xE1E425C5,
    0x22242606,
    0x80800080,
    0xA1AC2D8D,
    0xD3DC1FCF,
    0xA1A02181,
    0x30303000,
    0x33343707,
    0xA2AC2E8E,
    0x32343606,
    0x11141505,
    0x22202202,
    0x30383808,
    0xF0F434C4,
    0xA3A42787,
    0x41440545,
    0x404C0C4C,
    0x81800181,
    0xE1E829C9,
    0x80840484,
    0x93941787,
    0x31343505,
    0xC3C80BCB,
    0xC2CC0ECE,
    0x303C3C0C,
    0x71703141,
    0x11101101,
    0xC3C407C7,
    0x81880989,
    0x71743545,
    0xF3F83BCB,
    0xD2D81ACA,
    0xF0F838C8,
    0x90941484,
    0x51581949,
    0x82800282,
    0xC0C404C4,
    0xF3FC3FCF,
    0x41480949,
    0x31383909,
    0x63642747,
    0xC0C000C0,
    0xC3CC0FCF,
    0xD3D417C7,
    0xB0B83888,
    0x030C0F0F,
    0x828C0E8E,
    0x42400242,
    0x23202303,
    0x91901181,
    0x606C2C4C,
    0xD3D81BCB,
    0xA0A42484,
    0x30343404,
    0xF1F031C1,
    0x40480848,
    0xC2C002C2,
    0x636C2F4F,
    0x313C3D0D,
    0x212C2D0D,
    0x40400040,
    0xB2BC3E8E,
    0x323C3E0E,
    0xB0BC3C8C,
    0xC1C001C1,
    0xA2A82A8A,
    0xB2B83A8A,
    0x424C0E4E,
    0x51541545,
    0x33383B0B,
    0xD0DC1CCC,
    0x60682848,
    0x737C3F4F,
    0x909C1C8C,
    0xD0D818C8,
    0x42480A4A,
    0x52541646,
    0x73743747,
    0xA0A02080,
    0xE1EC2DCD,
    0x42440646,
    0xB1B43585,
    0x23282B0B,
    0x61642545,
    0xF2F83ACA,
    0xE3E023C3,
    0xB1B83989,
    0xB1B03181,
    0x939C1F8F,
    0x525C1E4E,
    0xF1F839C9,
    0xE2E426C6,
    0xB2B03282,
    0x31303101,
    0xE2E82ACA,
    0x616C2D4D,
    0x535C1F4F,
    0xE0E424C4,
    0xF0F030C0,
    0xC1CC0DCD,
    0x80880888,
    0x12141606,
    0x32383A0A,
    0x50581848,
    0xD0D414C4,
    0x62602242,
    0x21282909,
    0x03040707,
    0x33303303,
    0xE0E828C8,
    0x13181B0B,
    0x01040505,
    0x71783949,
    0x90901080,
    0x62682A4A,
    0x22282A0A,
    0x92981A8A,
]

SS3 = [
    0x08303838,
    0xC8E0E828,
    0x0D212C2D,
    0x86A2A426,
    0xCFC3CC0F,
    0xCED2DC1E,
    0x83B3B033,
    0x88B0B838,
    0x8FA3AC2F,
    0x40606020,
    0x45515415,
    0xC7C3C407,
    0x44404404,
    0x4F636C2F,
    0x4B63682B,
    0x4B53581B,
    0xC3C3C003,
    0x42626022,
    0x03333033,
    0x85B1B435,
    0x09212829,
    0x80A0A020,
    0xC2E2E022,
    0x87A3A427,
    0xC3D3D013,
    0x81919011,
    0x01111011,
    0x06020406,
    0x0C101C1C,
    0x8CB0BC3C,
    0x06323436,
    0x4B43480B,
    0xCFE3EC2F,
    0x88808808,
    0x4C606C2C,
    0x88A0A828,
    0x07131417,
    0xC4C0C404,
    0x06121416,
    0xC4F0F434,
    0xC2C2C002,
    0x45414405,
    0xC1E1E021,
    0xC6D2D416,
    0x0F333C3F,
    0x0D313C3D,
    0x8E828C0E,
    0x88909818,
    0x08202828,
    0x4E424C0E,
    0xC6F2F436,
    0x0E323C3E,
    0x85A1A425,
    0xC9F1F839,
    0x0D010C0D,
    0xCFD3DC1F,
    0xC8D0D818,
    0x0B23282B,
    0x46626426,
    0x4A72783A,
    0x07232427,
    0x0F232C2F,
    0xC1F1F031,
    0x42727032,
    0x42424002,
    0xC4D0D414,
    0x41414001,
    0xC0C0C000,
    0x43737033,
    0x47636427,
    0x8CA0AC2C,
    0x8B83880B,
    0xC7F3F437,
    0x8DA1AC2D,
    0x80808000,
    0x0F131C1F,
    0xCAC2C80A,
    0x0C202C2C,
    0x8AA2A82A,
    0x04303434,
    0xC2D2D012,
    0x0B03080B,
    0xCEE2EC2E,
    0xC9E1E829,
    0x4D515C1D,
    0x84909414,
    0x08101818,
    0xC8F0F838,
    0x47535417,
    0x8EA2AC2E,
    0x08000808,
    0xC5C1C405,
    0x03131013,
    0xCDC1CC0D,
    0x86828406,
    0x89B1B839,
    0xCFF3FC3F,
    0x4D717C3D,
    0xC1C1C001,
    0x01313031,
    0xC5F1F435,
    0x8A82880A,
    0x4A62682A,
    0x81B1B031,
    0xC1D1D011,
    0x00202020,
    0xC7D3D417,
    0x02020002,
    0x02222022,
    0x04000404,
    0x48606828,
    0x41717031,
    0x07030407,
    0xCBD3D81B,
    0x8D919C1D,
    0x89919819,
    0x41616021,
    0x8EB2BC3E,
    0xC6E2E426,
    0x49515819,
    0xCDD1DC1D,
    0x41515011,
    0x80909010,
    0xCCD0DC1C,
    0x8A92981A,
    0x83A3A023,
    0x8BA3A82B,
    0xC0D0D010,
    0x81818001,
    0x0F030C0F,
    0x47434407,
    0x0A12181A,
    0xC3E3E023,
    0xCCE0EC2C,
    0x8D818C0D,
    0x8FB3BC3F,
    0x86929416,
    0x4B73783B,
    0x4C505C1C,
    0x82A2A022,
    0x81A1A021,
    0x43636023,
    0x03232023,
    0x4D414C0D,
    0xC8C0C808,
    0x8E929C1E,
    0x8C909C1C,
    0x0A32383A,
    0x0C000C0C,
    0x0E222C2E,
    0x8AB2B83A,
    0x4E626C2E,
    0x8F939C1F,
    0x4A52581A,
    0xC2F2F032,
    0x82929012,
    0xC3F3F033,
    0x49414809,
    0x48707838,
    0xCCC0CC0C,
    0x05111415,
    0xCBF3F83B,
    0x40707030,
    0x45717435,
    0x4F737C3F,
    0x05313435,
    0x00101010,
    0x03030003,
    0x44606424,
    0x4D616C2D,
    0xC6C2C406,
    0x44707434,
    0xC5D1D415,
    0x84B0B434,
    0xCAE2E82A,
    0x09010809,
    0x46727436,
    0x09111819,
    0xCEF2FC3E,
    0x40404000,
    0x02121012,
    0xC0E0E020,
    0x8DB1BC3D,
    0x05010405,
    0xCAF2F83A,
    0x01010001,
    0xC0F0F030,
    0x0A22282A,
    0x4E525C1E,
    0x89A1A829,
    0x46525416,
    0x43434003,
    0x85818405,
    0x04101414,
    0x89818809,
    0x8B93981B,
    0x80B0B030,
    0xC5E1E425,
    0x48404808,
    0x49717839,
    0x87939417,
    0xCCF0FC3C,
    0x0E121C1E,
    0x82828002,
    0x01212021,
    0x8C808C0C,
    0x0B13181B,
    0x4F535C1F,
    0x47737437,
    0x44505414,
    0x82B2B032,
    0x0D111C1D,
    0x05212425,
    0x4F434C0F,
    0x00000000,
    0x46424406,
    0xCDE1EC2D,
    0x48505818,
    0x42525012,
    0xCBE3E82B,
    0x4E727C3E,
    0xCAD2D81A,
    0xC9C1C809,
    0xCDF1FC3D,
    0x00303030,
    0x85919415,
    0x45616425,
    0x0C303C3C,
    0x86B2B436,
    0xC4E0E424,
    0x8BB3B83B,
    0x4C707C3C,
    0x0E020C0E,
    0x40505010,
    0x09313839,
    0x06222426,
    0x02323032,
    0x84808404,
    0x49616829,
    0x83939013,
    0x07333437,
    0xC7E3E427,
    0x04202424,
    0x84A0A424,
    0xCBC3C80B,
    0x43535013,
    0x0A02080A,
    0x87838407,
    0xC9D1D819,
    0x4C404C0C,
    0x83838003,
    0x8F838C0F,
    0xCEC2CC0E,
    0x0B33383B,
    0x4A42480A,
    0x87B3B437,
]

# AhnLab's custom round constants (12 rounds)
ROUND_CONSTANTS = [
    (0x61C88647, 0x9E3779B9),  # Round 1
    (0xC3910C8D, 0x3C6EF373),  # Round 2
    (0x8722191A, 0x78DDE6E6),  # Round 3
    (0xE443234, 0xF1BBCDCC),  # Round 4
    (0x1C886467, 0xE3779B99),  # Round 5
    (0x3910C8CD, 0xC6EF3733),  # Round 6
    (0x72219199, 0x8DDE6E67),  # Round 7
    (0xE4432331, 0x1BBCDCCF),  # Round 8
    (0xC8864662, 0x3779B99E),  # Round 9
    (0x910C8CC4, 0x6EF3733C),  # Round 10
    (0x22191988, 0xDDE6E678),  # Round 11
    (0x4432330F, 0xBBCDCCF1),  # Round 12
]


def ahnlab_key_expand(user_key: bytes) -> bytes:
    """
    Exact implementation matching the C code with correct variable tracking
    """
    if len(user_key) != 16:
        raise ValueError(f"Key must be 16 bytes, got {len(user_key)}")

    # Initialize expanded_key_schedule (28 uint32s = 112 bytes)
    expanded = [0] * 28

    # Copy user key to first 4 positions
    expanded[0:4] = struct.unpack("<IIII", user_key)

    # Initialize from key
    uVar8 = expanded[0]
    uVar7 = expanded[1]
    uVar10 = expanded[2]
    uVar9 = expanded[3]

    # Round 1
    uVar1 = (uVar10 + uVar8 + 0x61C88647) & 0xFFFFFFFF
    uVar2 = ((uVar7 - uVar9) & 0xFFFFFFFF) + 0x9E3779B9
    uVar2 = uVar2 & 0xFFFFFFFF

    expanded[4] = (
        SS0[uVar1 & 0xFF]
        ^ SS1[(uVar1 >> 8) & 0xFF]
        ^ SS2[(uVar1 >> 0x10) & 0xFF]
        ^ SS3[uVar1 >> 0x18]
    )

    expanded[5] = (
        SS3[uVar2 >> 0x18]
        ^ SS0[uVar2 & 0xFF]
        ^ SS1[(uVar2 >> 8) & 0xFF]
        ^ SS2[(uVar2 >> 0x10) & 0xFF]
    )

    # After Round 1, uVar1 and uVar2 are reassigned
    uVar1 = ((uVar7 << 0x18) ^ (uVar8 >> 8)) & 0xFFFFFFFF
    uVar2 = ((uVar8 << 0x18) ^ (uVar7 >> 8)) & 0xFFFFFFFF

    # Round 2
    uVar3 = (uVar10 + uVar1 + 0xC3910C8D) & 0xFFFFFFFF
    uVar4 = ((uVar2 - uVar9) & 0xFFFFFFFF) + 0x3C6EF373
    uVar4 = uVar4 & 0xFFFFFFFF

    expanded[6] = (
        SS3[uVar3 >> 0x18]
        ^ SS0[uVar3 & 0xFF]
        ^ SS1[(uVar3 >> 8) & 0xFF]
        ^ SS2[(uVar3 >> 0x10) & 0xFF]
    )

    expanded[7] = (
        SS3[uVar4 >> 0x18]
        ^ SS0[uVar4 & 0xFF]
        ^ SS1[(uVar4 >> 8) & 0xFF]
        ^ SS2[(uVar4 >> 0x10) & 0xFF]
    )

    # After Round 2, uVar3 and uVar4 are reassigned
    uVar3 = ((uVar9 >> 0x18) ^ (uVar10 << 8)) & 0xFFFFFFFF
    uVar4 = ((uVar10 >> 0x18) ^ (uVar9 << 8)) & 0xFFFFFFFF

    # Round 3
    uVar5 = (uVar3 + uVar1 + 0x8722191A) & 0xFFFFFFFF
    uVar6 = ((uVar2 - uVar4) & 0xFFFFFFFF) + 0x78DDE6E6
    uVar6 = uVar6 & 0xFFFFFFFF

    expanded[8] = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )

    expanded[9] = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )

    # After Round 3, uVar7 and uVar8 are reassigned
    uVar7 = (((uVar7 >> 8) << 0x18) ^ (uVar1 >> 8)) & 0xFFFFFFFF
    uVar8 = (((uVar8 >> 8) << 0x18) ^ (uVar2 >> 8)) & 0xFFFFFFFF

    # Round 4
    uVar5 = (uVar3 + uVar7 + 0xE443234) & 0xFFFFFFFF
    uVar6 = ((uVar8 - uVar4) & 0xFFFFFFFF) + 0xF1BBCDCC
    uVar6 = uVar6 & 0xFFFFFFFF

    expanded[10] = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )

    expanded[0xB] = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )

    # After Round 4, uVar9 and uVar10 are reassigned
    uVar9 = (
        (((uVar9 << 8) & 0xFFFFFFFF) >> 0x18) ^ ((uVar3 << 8) & 0xFFFFFFFF)
    ) & 0xFFFFFFFF
    uVar10 = (
        (((uVar10 << 8) & 0xFFFFFFFF) >> 0x18) ^ ((uVar4 << 8) & 0xFFFFFFFF)
    ) & 0xFFFFFFFF

    # Round 5
    uVar5 = (uVar9 + uVar7 + 0x1C886467) & 0xFFFFFFFF
    uVar6 = ((uVar8 - uVar10) & 0xFFFFFFFF) + 0xE3779B99
    uVar6 = uVar6 & 0xFFFFFFFF

    expanded[0xC] = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )

    expanded[0xD] = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )

    # After Round 5, uVar2 and uVar1 are reassigned (note the order!)
    uVar2 = (((uVar2 >> 8) << 0x18) ^ (uVar7 >> 8)) & 0xFFFFFFFF
    uVar1 = (((uVar1 >> 8) << 0x18) ^ (uVar8 >> 8)) & 0xFFFFFFFF

    # Round 6
    uVar5 = (uVar9 + uVar2 + 0x3910C8CD) & 0xFFFFFFFF
    uVar6 = ((uVar1 - uVar10) & 0xFFFFFFFF) + 0xC6EF3733
    uVar6 = uVar6 & 0xFFFFFFFF

    expanded[0xE] = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )

    expanded[0xF] = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )

    # After Round 6, uVar4 and uVar3 are reassigned
    uVar4 = (
        (((uVar4 << 8) & 0xFFFFFFFF) >> 0x18) ^ ((uVar9 << 8) & 0xFFFFFFFF)
    ) & 0xFFFFFFFF
    uVar3 = (
        (((uVar3 << 8) & 0xFFFFFFFF) >> 0x18) ^ ((uVar10 << 8) & 0xFFFFFFFF)
    ) & 0xFFFFFFFF

    # Round 7
    uVar5 = (uVar4 + uVar2 + 0x72219199) & 0xFFFFFFFF
    uVar6 = ((uVar1 - uVar3) & 0xFFFFFFFF) + 0x8DDE6E67
    uVar6 = uVar6 & 0xFFFFFFFF

    expanded[0x10] = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )

    expanded[0x11] = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )

    # After Round 7, uVar8 and uVar7 are reassigned
    uVar8 = (((uVar8 >> 8) << 0x18) ^ (uVar2 >> 8)) & 0xFFFFFFFF
    uVar7 = (((uVar7 >> 8) << 0x18) ^ (uVar1 >> 8)) & 0xFFFFFFFF

    # Round 8
    uVar5 = (uVar4 + uVar8 + 0xE4432331) & 0xFFFFFFFF
    uVar6 = ((uVar7 - uVar3) & 0xFFFFFFFF) + 0x1BBCDCCF
    uVar6 = uVar6 & 0xFFFFFFFF

    expanded[0x12] = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )

    expanded[0x13] = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )

    # After Round 8, uVar10 and uVar9 are reassigned
    uVar10 = (
        (((uVar10 << 8) & 0xFFFFFFFF) >> 0x18) ^ ((uVar4 << 8) & 0xFFFFFFFF)
    ) & 0xFFFFFFFF
    uVar9 = (
        (((uVar9 << 8) & 0xFFFFFFFF) >> 0x18) ^ ((uVar3 << 8) & 0xFFFFFFFF)
    ) & 0xFFFFFFFF

    # Round 9
    uVar5 = (uVar10 + uVar8 + 0xC8864662) & 0xFFFFFFFF
    uVar6 = ((uVar7 - uVar9) & 0xFFFFFFFF) + 0x3779B99E
    uVar6 = uVar6 & 0xFFFFFFFF

    expanded[0x14] = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )

    expanded[0x15] = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )

    # After Round 9, uVar1 and uVar2 are reassigned
    uVar1 = (((uVar1 >> 8) << 0x18) ^ (uVar8 >> 8)) & 0xFFFFFFFF
    uVar2 = (((uVar2 >> 8) << 0x18) ^ (uVar7 >> 8)) & 0xFFFFFFFF

    # Round 10
    uVar5 = (uVar10 + uVar1 + 0x910C8CC4) & 0xFFFFFFFF
    uVar6 = ((uVar2 - uVar9) & 0xFFFFFFFF) + 0x6EF3733C
    uVar6 = uVar6 & 0xFFFFFFFF

    expanded[0x16] = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )

    expanded[0x17] = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )

    # After Round 10, NEW VARIABLES: uVar10 and uVar9 use uVar3 and uVar4!
    uVar10 = (
        (((uVar3 << 8) & 0xFFFFFFFF) >> 0x18) ^ ((uVar10 << 8) & 0xFFFFFFFF)
    ) & 0xFFFFFFFF
    uVar9 = (
        (((uVar4 << 8) & 0xFFFFFFFF) >> 0x18) ^ ((uVar9 << 8) & 0xFFFFFFFF)
    ) & 0xFFFFFFFF

    # Round 11
    uVar3 = (uVar10 + uVar1 + 0x22191988) & 0xFFFFFFFF
    uVar4 = ((uVar2 - uVar9) & 0xFFFFFFFF) + 0xDDE6E678
    uVar4 = uVar4 & 0xFFFFFFFF

    expanded[0x18] = (
        SS3[uVar3 >> 0x18]
        ^ SS0[uVar3 & 0xFF]
        ^ SS1[(uVar3 >> 8) & 0xFF]
        ^ SS2[(uVar3 >> 0x10) & 0xFF]
    )

    expanded[0x19] = (
        SS3[uVar4 >> 0x18]
        ^ SS0[uVar4 & 0xFF]
        ^ SS1[(uVar4 >> 8) & 0xFF]
        ^ SS2[(uVar4 >> 0x10) & 0xFF]
    )

    # Round 12 (final) - note the complex inline calculations
    uVar7 = (uVar10 + (((uVar7 >> 8) << 0x18) ^ (uVar1 >> 8)) + 0x4432330F) & 0xFFFFFFFF
    uVar8 = ((((uVar8 >> 8) << 0x18) ^ (uVar2 >> 8)) - uVar9) & 0xFFFFFFFF
    uVar8 = (uVar8 + 0xBBCDCCF1) & 0xFFFFFFFF

    expanded[0x1A] = (
        SS3[uVar7 >> 0x18]
        ^ SS0[uVar7 & 0xFF]
        ^ SS1[(uVar7 >> 8) & 0xFF]
        ^ SS2[(uVar7 >> 0x10) & 0xFF]
    )

    expanded[0x1B] = (
        SS3[uVar8 >> 0x18]
        ^ SS0[uVar8 & 0xFF]
        ^ SS1[(uVar8 >> 8) & 0xFF]
        ^ SS2[(uVar8 >> 0x10) & 0xFF]
    )

    # Convert back to bytes
    return struct.pack("<28I", *expanded)


def ahnlab_seed_decrypt_block(block: bytes, key_schedule: bytes) -> bytes:
    """
    AhnLab's seedDecrypt - exact implementation from decompiled code
    """
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")

    # Parse input block as 4 uint32s (big-endian)
    param_1 = list(struct.unpack("<IIII", block))

    # Parse key schedule
    param_2 = key_schedule

    # Helper to get key at offset
    def get_key(offset):
        return struct.unpack("<I", param_2[offset : offset + 4])[0]

    # Round 1
    uVar5 = get_key(0x6C) ^ param_1[1]
    uVar6 = get_key(0x68) ^ param_1[0] ^ uVar5
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar5 = (uVar5 + uVar6) & 0xFFFFFFFF
    uVar5 = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )
    uVar6 = (uVar6 + uVar5) & 0xFFFFFFFF
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar1 = param_1[2] ^ uVar6
    uVar2 = param_1[3] ^ ((uVar5 + uVar6) & 0xFFFFFFFF)

    # Round 2
    uVar5 = get_key(100) ^ uVar2  # 0x64 = 100
    uVar6 = get_key(0x60) ^ uVar1 ^ uVar5
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar5 = (uVar5 + uVar6) & 0xFFFFFFFF
    uVar5 = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )
    uVar6 = (uVar6 + uVar5) & 0xFFFFFFFF
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar3 = param_1[0] ^ uVar6
    uVar4 = param_1[1] ^ ((uVar5 + uVar6) & 0xFFFFFFFF)

    # Round 3
    uVar5 = get_key(0x5C) ^ uVar4
    uVar6 = get_key(0x58) ^ uVar3 ^ uVar5
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar5 = (uVar5 + uVar6) & 0xFFFFFFFF
    uVar5 = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )
    uVar6 = (uVar6 + uVar5) & 0xFFFFFFFF
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar1 = uVar1 ^ uVar6
    uVar2 = uVar2 ^ ((uVar5 + uVar6) & 0xFFFFFFFF)

    # Round 4
    uVar5 = get_key(0x54) ^ uVar2
    uVar6 = get_key(0x50) ^ uVar1 ^ uVar5
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar5 = (uVar5 + uVar6) & 0xFFFFFFFF
    uVar5 = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )
    uVar6 = (uVar6 + uVar5) & 0xFFFFFFFF
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar3 = uVar3 ^ uVar6
    uVar4 = uVar4 ^ ((uVar5 + uVar6) & 0xFFFFFFFF)

    # Round 5
    uVar5 = get_key(0x4C) ^ uVar4
    uVar6 = get_key(0x48) ^ uVar3 ^ uVar5
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar5 = (uVar5 + uVar6) & 0xFFFFFFFF
    uVar5 = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )
    uVar6 = (uVar6 + uVar5) & 0xFFFFFFFF
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar1 = uVar1 ^ uVar6
    uVar2 = uVar2 ^ ((uVar5 + uVar6) & 0xFFFFFFFF)

    # Round 6
    uVar5 = get_key(0x44) ^ uVar2
    uVar6 = get_key(0x40) ^ uVar1 ^ uVar5
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar5 = (uVar5 + uVar6) & 0xFFFFFFFF
    uVar5 = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )
    uVar6 = (uVar6 + uVar5) & 0xFFFFFFFF
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar3 = uVar3 ^ uVar6
    uVar4 = uVar4 ^ ((uVar5 + uVar6) & 0xFFFFFFFF)

    # Round 7
    uVar5 = get_key(0x3C) ^ uVar4
    uVar6 = get_key(0x38) ^ uVar3 ^ uVar5
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar5 = (uVar5 + uVar6) & 0xFFFFFFFF
    uVar5 = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )
    uVar6 = (uVar6 + uVar5) & 0xFFFFFFFF
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar1 = uVar1 ^ uVar6
    uVar2 = uVar2 ^ ((uVar5 + uVar6) & 0xFFFFFFFF)

    # Round 8
    uVar5 = get_key(0x34) ^ uVar2
    uVar6 = get_key(0x30) ^ uVar1 ^ uVar5
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar5 = (uVar5 + uVar6) & 0xFFFFFFFF
    uVar5 = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )
    uVar6 = (uVar6 + uVar5) & 0xFFFFFFFF
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar3 = uVar3 ^ uVar6
    uVar4 = uVar4 ^ ((uVar5 + uVar6) & 0xFFFFFFFF)

    # Round 9
    uVar5 = get_key(0x2C) ^ uVar4
    uVar6 = get_key(0x28) ^ uVar3 ^ uVar5
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar5 = (uVar5 + uVar6) & 0xFFFFFFFF
    uVar5 = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )
    uVar6 = (uVar6 + uVar5) & 0xFFFFFFFF
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar1 = uVar1 ^ uVar6
    uVar2 = uVar2 ^ ((uVar5 + uVar6) & 0xFFFFFFFF)

    # Round 10
    uVar5 = get_key(0x24) ^ uVar2
    uVar6 = get_key(0x20) ^ uVar1 ^ uVar5
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar5 = (uVar5 + uVar6) & 0xFFFFFFFF
    uVar5 = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )
    uVar6 = (uVar6 + uVar5) & 0xFFFFFFFF
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar3 = uVar3 ^ uVar6
    uVar4 = uVar4 ^ ((uVar5 + uVar6) & 0xFFFFFFFF)

    # Round 11
    uVar5 = get_key(0x1C) ^ uVar4
    uVar6 = get_key(0x18) ^ uVar3 ^ uVar5
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar5 = (uVar5 + uVar6) & 0xFFFFFFFF
    uVar5 = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )
    uVar6 = (uVar6 + uVar5) & 0xFFFFFFFF
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar1 = uVar1 ^ uVar6
    uVar2 = uVar2 ^ ((uVar5 + uVar6) & 0xFFFFFFFF)

    # Round 12 (final)
    uVar5 = get_key(0x14) ^ uVar2
    uVar6 = get_key(0x10) ^ uVar1 ^ uVar5
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )
    uVar5 = (uVar5 + uVar6) & 0xFFFFFFFF
    uVar5 = (
        SS3[uVar5 >> 0x18]
        ^ SS0[uVar5 & 0xFF]
        ^ SS1[(uVar5 >> 8) & 0xFF]
        ^ SS2[(uVar5 >> 0x10) & 0xFF]
    )
    uVar6 = (uVar6 + uVar5) & 0xFFFFFFFF
    uVar6 = (
        SS3[uVar6 >> 0x18]
        ^ SS0[uVar6 & 0xFF]
        ^ SS1[(uVar6 >> 8) & 0xFF]
        ^ SS2[(uVar6 >> 0x10) & 0xFF]
    )

    # Final output
    param_1[0] = uVar1
    param_1[1] = uVar2
    param_1[2] = uVar3 ^ uVar6
    param_1[3] = uVar4 ^ ((uVar5 + uVar6) & 0xFFFFFFFF)

    return struct.pack("<IIII", *param_1)


def ahnlab_seed_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt using AhnLab's custom SEED in CBC mode
    (Standard CBC - kept for reference)
    """
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext must be multiple of 16 bytes")

    # Expand key
    key_schedule = ahnlab_key_expand(key)

    # Decrypt blocks
    plaintext = bytearray()
    prev_block = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i + 16]

        # Decrypt block
        decrypted = ahnlab_seed_decrypt_block(block, key_schedule)

        # XOR with previous ciphertext block (CBC)
        plaintext_block = bytes(a ^ b for a, b in zip(decrypted, prev_block))
        plaintext.extend(plaintext_block)

        prev_block = block

    # Remove PKCS#7 padding
    if plaintext:
        padding_len = plaintext[-1]
        if 1 <= padding_len <= 16:
            # Verify padding
            if all(b == padding_len for b in plaintext[-padding_len:]):
                plaintext = plaintext[:-padding_len]

    return bytes(plaintext)


def ahnlab_seedcipher_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt using AhnLab's seedCipher - to be implemented to match binary exactly
    """
    # TODO: Implement the exact seedCipher algorithm by analyzing the binary step-by-step
    pass


def main():
    """Test decryption of astxcfg.dat"""
    import os

    # AhnLab's key and IV
    key = b"AhnlabSecretKey\x00"
    iv = bytes([1, 2, 3, 4] + [0] * 12)

    result = ahnlab_key_expand(key)

    print("Final corrected implementation output:")
    for i in range(0, 112, 16):
        row = result[i : min(i + 16, 112)]
        print(f"  {row.hex(' ')}")

    # Compare with Ghidra
    ghidra_key = """41 68 6e 6c 61 62 53 65 63 72 65 74 4b 65 79 00
    2f dd b1 23 d4 37 85 37 89 e0 75 f2 26 b7 30 01
    02 1a b1 01 f4 b2 cf 15 a9 2f 42 47 b0 b4 fc 74
    5d 25 dc 1e 06 d5 2e 4b 99 b2 22 d1 2d 3a a4 c2
    bc 5d 6f f1 fe dc 1a a6 65 8f f8 9c 95 7e 4e 2c
    e4 04 23 ad 9f 81 0f 14 f2 0b 06 9a 21 d0 b4 a4
    b7 5a 13 12 d8 5f 54 6c 3b bd c2 81 5b 08 a3 7a"""

    ghidra_bytes = bytes.fromhex(ghidra_key.replace(" ", "").replace("\n", ""))

    if result == ghidra_bytes:
        print("\n✅ MATCHES GHIDRA EXACTLY!")
    else:
        print("\n❌ Still differs from Ghidra")
        for i in range(112):
            if result[i] != ghidra_bytes[i]:
                print(
                    f"First diff at byte {i}: Fixed=0x{result[i]:02x}, Ghidra=0x{ghidra_bytes[i]:02x}"
                )
                print(f"Position {i // 4}, offset {i % 4}")
                break

    # Read encrypted file
    cfg_path = "/Users/robertothais/code/src/work/breakwater/targets/astx/specimen/cfg/astxcfg.dat"

    if not os.path.exists(cfg_path):
        print(f"File not found: {cfg_path}")
        return

    with open(cfg_path, "rb") as f:
        ciphertext = f.read()

    print(f"\nEncrypted file size: {len(ciphertext)} bytes")

    # Display encrypted blocks
    print("\nEncrypted blocks:")
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i + 16]
        print(f"  Block {i // 16 + 1}: {block.hex(' ')}")

    try:
        # Decrypt
        plaintext = ahnlab_seed_cbc_decrypt(ciphertext, key, iv)

        print(f"\nDecrypted size: {len(plaintext)} bytes")

        # Display decrypted blocks
        print("\nDecrypted blocks:")
        for i in range(0, len(plaintext), 16):
            block = plaintext[i : i + 16]
            print(f"  Block {i // 16 + 1}: {block.hex(' ')}")

        # Try to decode as text
        try:
            text = plaintext.decode("utf-8")
            print(f"\nDecrypted content:\n{text}")
        except UnicodeDecodeError:
            print(f"\nDecrypted (hex): {plaintext.hex()}")
            print("Note: Content is not valid UTF-8 text")

    except Exception as e:
        print(f"Decryption failed: {e}")
        import traceback

        traceback.print_exc()


def test_seedcipher_vs_binary():
    """Test our seedCipher implementation against known binary output"""
    print("\n" + "=" * 60)
    print("TESTING SEEDCIPHER VS BINARY OUTPUT")
    print("=" * 60)

    # Test data from binary
    key = b"AhnlabSecretKey\x00"
    iv = bytes([1, 2, 3, 4] + [0] * 12)

    # astxcfg.dat ciphertext (64 bytes)
    ciphertext = bytes(
        [
            0x62,
            0xC8,
            0x60,
            0x80,
            0x2D,
            0x83,
            0x93,
            0xC5,
            0x5E,
            0xD5,
            0xFE,
            0xA4,
            0x2B,
            0x01,
            0x07,
            0xF3,
            0x30,
            0xA2,
            0x6F,
            0xE5,
            0x8F,
            0xBA,
            0x68,
            0x14,
            0x07,
            0x7C,
            0xE2,
            0xDA,
            0x93,
            0xC7,
            0xE0,
            0x23,
            0xA5,
            0xA1,
            0x96,
            0xE7,
            0x45,
            0x47,
            0x2C,
            0x18,
            0x88,
            0xD9,
            0x90,
            0x10,
            0xA6,
            0xE2,
            0x5F,
            0xD1,
            0x18,
            0x1F,
            0x58,
            0x93,
            0x85,
            0x1D,
            0xEB,
            0xA0,
            0xCB,
            0xF1,
            0x5B,
            0xC9,
            0xCF,
            0x6E,
            0xE7,
            0xAA,
        ]
    )

    # Expected output from binary seedCipher
    expected_output = bytes.fromhex(
        "fcc7e8bd31ca6da42cbd688a2ded6f93"
        + "952cf230a78cdaa6933a11487f40d3e7"
        + "9fbbf6d4117fe36ef11af41d252ac408"
        + "609269fdc1d08eabb80e9e88efa1aaa9"
    )

    print(f"Input ciphertext ({len(ciphertext)} bytes):")
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i + 16]
        print(f"  Block {i // 16 + 1}: {block.hex()}")

    print(f"\nExpected binary output ({len(expected_output)} bytes):")
    for i in range(0, len(expected_output), 16):
        block = expected_output[i : i + 16]
        print(f"  Block {i // 16 + 1}: {block.hex()}")

    # Test our seedCipher implementation
    our_output = ahnlab_seedcipher_decrypt(ciphertext, key, iv)

    print(f"\nOur seedCipher output ({len(our_output)} bytes):")
    for i in range(0, len(our_output), 16):
        block = our_output[i : i + 16]
        print(f"  Block {i // 16 + 1}: {block.hex()}")

    # Compare results
    if our_output == expected_output:
        print("\n🎉 SUCCESS! Our seedCipher implementation EXACTLY matches the binary!")
        print("✅ We have successfully reverse engineered AhnLab's seedCipher!")
    else:
        print(f"\n❌ Mismatch detected!")
        print(f"Expected: {expected_output.hex()}")
        print(f"Got:      {our_output.hex()}")

        # Show byte-by-byte differences
        min_len = min(len(expected_output), len(our_output))
        differences = 0
        for i in range(min_len):
            if expected_output[i] != our_output[i]:
                if differences < 10:  # Show first 10 differences
                    print(
                        f"  Diff at byte {i}: expected 0x{expected_output[i]:02x}, got 0x{our_output[i]:02x}"
                    )
                differences += 1

        if differences > 10:
            print(f"  ... and {differences - 10} more differences")

        print(f"Total differences: {differences}/{min_len} bytes")


if __name__ == "__main__":
    main()
    test_seedcipher_vs_binary()

#
# THIS IS THE VERIFIED OUTPUT STRAIGHT FROM THE BINARY FROM GHIDRA
# THIS IS WHAT THIS PYTHON FILE SHOULD PRODUCE
#
# ===========================================================
# Test complete!
# SEEDCompare.py> Finished!
# SEEDCompare.py> Running...
# ============================================================
# Testing AhnLab SEED Implementation
# ============================================================

# 1. Testing seedKeyExpand with multiple keys

#    Key 1 (AhnlabSecretKey):
#    Input key: 41686e6c61625365637265744b657900
#    Found seedKeyExpand at 08105c2d
#    Calling seedKeyExpand...
#    Expanded key schedule (hex):
#      41 68 6e 6c 61 62 53 65 63 72 65 74 4b 65 79 00
#      2f dd b1 23 d4 37 85 37 89 e0 75 f2 26 b7 30 01
#      02 1a b1 01 f4 b2 cf 15 a9 2f 42 47 b0 b4 fc 74
#      5d 25 dc 1e 06 d5 2e 4b 99 b2 22 d1 2d 3a a4 c2
#      bc 5d 6f f1 fe dc 1a a6 65 8f f8 9c 95 7e 4e 2c
#      e4 04 23 ad 9f 81 0f 14 f2 0b 06 9a 21 d0 b4 a4
#      b7 5a 13 12 d8 5f 54 6c 3b bd c2 81 5b 08 a3 7a

#    Key 2 (all zeros):
#    Input key: 00000000000000000000000000000000
#    Calling seedKeyExpand...
#    Expanded key schedule (hex):
#      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#      7e 8c 8f 7c 2c a2 37 c7 db 6c 27 ff 4a 68 ca a7
#      a1 01 9d 2f 41 9e 04 70 c4 b3 59 ae 0c e9 45 42
#      0f 40 d6 a1 4e 39 c1 db 08 35 96 85 cb 1f 5f 0c
#      a7 bd 84 b6 ae ae a4 61 41 07 7e d1 a1 0a e9 fe
#      d5 05 cc 76 94 73 7a e9 92 6f ac 50 e5 66 26 1b
#      4a 90 b7 65 b3 a7 c3 8e 22 2e 7e 2f b9 21 b1 a2

#    Key 3 (all ones):
#    Input key: ffffffffffffffffffffffffffffffff
#    Calling seedKeyExpand...
#    Expanded key schedule (hex):
#      ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
#      86 7d 46 45 2c a2 37 c7 bf 0d 62 da 4a 68 ca a7
#      05 a3 1b 09 41 9e 04 70 a4 d0 1a 8d 0c e9 45 42
#      2f 60 d6 81 4e 39 c1 db 70 46 dd be cb 1f 5f 0c
#      3b 2e 0b a9 ae ae a4 61 5d 16 73 cc a1 0a e9 fe
#      05 d7 0e 64 94 73 7a e9 b6 4c ab 77 e5 66 26 1b
#      4e 90 b3 61 b3 a7 c3 8e be bd f1 30 b9 21 b1 a2

#    Key 4 (sequential):
#    Input key: 0102030405060708090a0b0c0d0e0f10
#    Calling seedKeyExpand...
#    Expanded key schedule (hex):
#      01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10
#      01 9d 44 16 a0 33 e0 5a 45 60 c0 90 ec 74 e2 b7
#      b6 dc 0e b6 81 21 74 86 74 48 7e 75 67 71 65 90
#      c0 f1 00 df 3d 16 25 7e fc 87 b5 99 73 19 45 40
#      07 a8 66 9a ef 42 30 65 cf 99 46 96 49 3b 47 51
#      35 ba 3f 8e e6 9c 67 51 1f c1 a5 0e 1b 56 bb 4d
#      42 b9 8a fe 65 f4 11 86 9b 70 f8 1f 9e 99 7a 59

#    Key 5 (repeated 0xAA):
#    Input key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
#    Calling seedKeyExpand...
#    Expanded key schedule (hex):
#      aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa
#      a9 9c 76 f2 2c a2 37 c7 1c 0a 83 64 4a 68 ca a7
#      12 11 37 4f 41 9e 04 70 7d ea e0 24 0c e9 45 42
#      31 d1 f9 cb 4e 39 c1 db 93 a8 95 39 cb 1f 5f 0c
#      b4 3d 76 33 ae ae a4 61 8e 62 49 14 a1 0a e9 fe
#      3c eb 21 49 94 73 7a e9 b8 6a 67 b8 e5 66 26 1b
#      c4 a8 f4 15 b3 a7 c3 8e 6c ed 93 29 b9 21 b1 a2

# 2. Testing seedDecrypt

#    Resetting to AhnlabSecretKey for decrypt tests...
#    Using AhnlabSecretKey schedule for all decrypt tests
#    Found seedDecrypt at 08104f66

#    Testing: astxcfg.dat block 1
#    Input block: 62c860802d8393c55ed5fea42b0107f3
#    Output block: 24e6e18baebf37952cfedabf26350ad8

#    Testing: all zeros
#    Input block: 00000000000000000000000000000000
#    Output block: d97c390c633656dcc42c0b93152cf72a

#    Testing: all ones
#    Input block: ffffffffffffffffffffffffffffffff
#    Output block: 2c7284756ff65c431064b696f898fd4e

#    Testing: astxcfg.dat block 2
#    Input block: 30a26fe58fba6814077ce2da93c7e023
#    Output block: a696f8651feeddb9ca280239e3afc2a9

#    Testing: alternating pattern
#    Input block: 0123456789abcdef0123456789abcdef
#    Output block: 58c6eb428191bf499edd323b44d77627

#    Testing: mixed hex values
#    Input block: deadbeefcafebabe1234567890abcdef
#    Output block: fab68c70fd0a0b0b07be6e32667ee9cf

#    Testing: repeated 0xa5
#    Input block: a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5
#    Output block: 5478f6b5737e443cabea7a37ef1ceba1

#    Testing: 0x55/0xaa pattern
#    Input block: 5555555555555555aaaaaaaaaaaaaaaa
#    Output block: 0f6cd5f1f3a0dee7a4d7a2f4fef98bb8

# 3. Testing CBC mode on full astxcfg.dat
#    ----------------------------------------
#    Using binary IV: 01020304000000000000000000000000
#    Decrypting with proper CBC chaining:

#    Block 1:
#      Decrypted: 25e4e28faebf37952cfedabf26350ad8

#    Block 2:
#      Decrypted: 963497809054b5adcd54e0e37068228a

#    Block 3:
#      Decrypted: 5d00278d8aa37febf4ef56dbe2d3560c

#    Block 4:
#      Decrypted: dfe1c5f71db424abb5b06f8055fd9da9

# 4. Testing seedCipher function directly
#    ----------------------------------------

#    Setting up seedCipher test with astxcfg.dat data...
#    Found seedCipher at 08106983
#    Calling seedCipher with 64 bytes of astxcfg.dat...
#    seedCipher return value: 0 (0x0)
#    seedCipher output (64 bytes):
#      fc c7 e8 bd 31 ca 6d a4 2c bd 68 8a 2d ed 6f 93
#      95 2c f2 30 a7 8c da a6 93 3a 11 48 7f 40 d3 e7
#      9f bb f6 d4 11 7f e3 6e f1 1a f4 1d 25 2a c4 08
#      60 92 69 fd c1 d0 8e ab b8 0e 9e 88 ef a1 aa a9
#    This is what we need to reproduce in our Python implementation!

# ============================================================
# Test complete!
# SEEDCompare.py> Finished!
