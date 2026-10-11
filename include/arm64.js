function int32ToHex(value) {
    return '0x' + (value >>> 0).toString(16).padStart(8, '0');
}

function hexToInt32(hex) {
    let s = String(hex).trim().replace(/^0x/i, '');
    let value = parseInt(s, 16) >>> 0;
    return value > 0x7fffffff ? value - 0x100000000 : value;
}

function reverseBytes(value) {
    value >>>= 0;
    return (((value & 0xff) << 24) |
        ((value & 0xff00) << 8) |
        ((value >>> 8) & 0xff00) |
        ((value >>> 24) & 0xff)) >>> 0;
}

function signExtend(value, bits) {
    let sign = 1 << (bits - 1);
    return (value & sign) ? value - (1 << bits) : value;
}

function parseImm(s) {
    s = String(s).replace(/^#/, '');
    let sign = 1;
    if (s.startsWith('-') || s.startsWith('+')) {
        sign = s.startsWith('-') ? -1 : 1;
        s = s.slice(1);
    }
    let radix = 10;
    if (s.startsWith('0x') || s.startsWith('0X')) { radix = 16; s = s.slice(2); }
    else if (s.startsWith('0b') || s.startsWith('0B')) { radix = 2; s = s.slice(2); }
    else if (s.startsWith('0o') || s.startsWith('0O')) { radix = 8; s = s.slice(2); }
    return sign * parseInt(s, radix);
}

function immStr(n) {
    return n < 0 ? `#-${Math.abs(n)}` : `#${n}`;
}

function matches(value, mask, expected) {
    return ((value & mask) >>> 0) === (expected >>> 0);
}

function reg(prefix, n, zr31 = true) {
    if (n === 31 && zr31) return prefix === 'x' ? 'xzr' : 'wzr';
    return `${prefix}${n}`;
}

function parseReg(s) {
    s = String(s).toLowerCase().trim();
    if (s === 'sp' || s === 'wsp') return { num: 31, size: s === 'sp' ? 64 : 32, sp: true };
    if (s === 'xzr') return { num: 31, size: 64, zr: true };
    if (s === 'wzr') return { num: 31, size: 32, zr: true };
    let m = s.match(/^([xw])([0-9]|[12][0-9]|3[01])$/);
    if (!m) throw new Error(`Bad register: ${s}`);
    return { num: parseInt(m[2], 10), size: m[1] === 'x' ? 64 : 32 };
}

function parseSimdReg(s) {
    s = String(s).toLowerCase().trim();
    let m = s.match(/^([bhsdqv])([0-9]|[12][0-9]|3[01])(\.[0-9a-z]+)?$/);
    if (!m) throw new Error(`Bad SIMD/FP register: ${s}`);
    return { num: parseInt(m[2], 10), prefix: m[1], arrangement: m[3] ? m[3].slice(1) : null };
}

function splitOps(text) {
    let out = [], cur = '', depth = 0;
    for (let ch of text) {
        if (ch === '[' || ch === '{') depth++;
        if (ch === ']' || ch === '}') depth--;
        if (ch === ',' && depth === 0) {
            out.push(cur.trim());
            cur = '';
        } else {
            cur += ch;
        }
    }
    if (cur.trim()) out.push(cur.trim());
    return out;
}

function parseInstruction(instruction) {
    instruction = String(instruction).toLowerCase().replace(/;.*$/, '').trim();
    let m = instruction.match(/^([a-z0-9.]+)(?:\s+(.*))?$/);
    if (!m) throw new Error('Empty instruction');
    return { mnemonic: m[1], ops: m[2] ? splitOps(m[2]) : [] };
}

const fixedArm64 = {
    nop: 0xd503201f,

    pacia1716: 0xd503211f,
    pacib1716: 0xd503215f,
    autia1716: 0xd503219f,
    autib1716: 0xd50321df,
    paciaz: 0xd503231f,
    paciasp: 0xd503233f,
    pacibz: 0xd503235f,
    pacibsp: 0xd503237f,
    autiaz: 0xd503239f,
    autiasp: 0xd50323bf,
    autibz: 0xd50323df,
    autibsp: 0xd50323ff,
    xpaclri: 0xd50320ff,
    bti: 0xd503241f,
    'bti c': 0xd503245f,
    'bti j': 0xd503249f,
    'bti jc': 0xd50324df,
    csdb: 0xd503229f,
    sb: 0xd50330ff,
    yield: 0xd503203f,
    wfe: 0xd503205f,
    wfi: 0xd503207f,
    sev: 0xd503209f,
    sevl: 0xd50320bf,
    clrex: 0xd5033f5f,
    ret: 0xd65f03c0,
    retaa: 0xd65f0bff,
    retab: 0xd65f0fff
};

const systemRegToEncoding = {
    tpidr_el0: 0xd53bd040,
    tpidrro_el0: 0xd53bd060,
    tpidr_el1: 0xd538d080,
    cntvct_el0: 0xd53be040,
    cntfrq_el0: 0xd53be000,
    cntpct_el0: 0xd53be020,
    fpcr: 0xd53b4400,
    fpsr: 0xd53b4420,
    nzcv: 0xd53b4200,
    currentel: 0xd5384240,
    daif: 0xd53b4220,
    midr_el1: 0xd5380000,
    mpidr_el1: 0xd53800a0,
    sctlr_el1: 0xd5381000,
    ttbr0_el1: 0xd5382000,
    ttbr1_el1: 0xd5382020,
    tcr_el1: 0xd5382040,
    esr_el1: 0xd5385200,
    far_el1: 0xd5386000,
    vbar_el1: 0xd538c000,
    elr_el1: 0xd5384020,
    spsr_el1: 0xd5384000,
    sp_el0: 0xd5384100,
    cpacr_el1: 0xd5381040
};

const systemEncodingToReg = Object.fromEntries(
    Object.entries(systemRegToEncoding).map(([name, enc]) => [enc >>> 0, name])
);

function genericSysRegToFields(name) {
    let m = /^s([23])_([0-7])_c(\d+)_c(\d+)_([0-7])$/i.exec(name);
    if (!m) return null;
    let op0 = parseInt(m[1], 10), op1 = parseInt(m[2], 10);
    let crn = parseInt(m[3], 10), crm = parseInt(m[4], 10), op2 = parseInt(m[5], 10);
    if (crn > 15 || crm > 15) return null;
    let o0 = op0 - 2;
    return (o0 << 19) | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5);
}

function genericSysRegFieldsToName(value) {
    let o0 = (value >>> 19) & 1, op1 = (value >>> 16) & 7;
    let crn = (value >>> 12) & 0xf, crm = (value >>> 8) & 0xf, op2 = (value >>> 5) & 7;
    return `s${2 + o0}_${op1}_c${crn}_c${crm}_${op2}`;
}

function decodeLoadStoreUnsigned(value) {
    let size = (value >>> 30) & 3;
    let v = (value >>> 26) & 1;
    let opc = (value >>> 22) & 3;
    if (v) return null;
    let imm12 = (value >>> 10) & 0xfff;
    let rn = (value >>> 5) & 0x1f;
    let rt = value & 0x1f;
    let scale = size;
    let offset = imm12 << scale;
    let rnReg = rn === 31 ? 'sp' : `x${rn}`;
    let addr = offset ? `[${rnReg}, #${offset}]` : `[${rnReg}]`;
    if (size === 2 && opc === 2) {
        return `ldrsw x${rt}, ${addr}`;
    }
    if (size === 2 && opc === 3) return null;
    if (size === 1 && opc === 2) return `ldrsh x${rt}, ${addr}`;
    if (size === 1 && opc === 3) return `ldrsh w${rt}, ${addr}`;
    if (size === 0 && opc === 2) return `ldrsb x${rt}, ${addr}`;
    if (size === 0 && opc === 3) return `ldrsb w${rt}, ${addr}`;
    if (size === 3 && opc === 2) {
        const typeNames = ['pld', 'pli', 'pst'];
        const targetNames = ['l1', 'l2', 'l3'];
        const policyNames = ['keep', 'strm'];
        let type = (rt >>> 3) & 3, target = (rt >>> 1) & 3, policy = rt & 1;
        if (type > 2 || target > 2) return `prfm #${rt}, ${addr}`;
        return `prfm ${typeNames[type]}${targetNames[target]}${policyNames[policy]}, ${addr}`;
    }
    if (size === 3 && opc === 3) return null;
    let load = (opc & 1) === 1;
    let mnemonic = loadStoreMnemonic(load, size);
    let prefix = loadStoreRegPrefix(size);
    return `${mnemonic} ${reg(prefix, rt)}, ${addr}`;
}

function loadStoreMnemonic(load, size) {
    if (size === 0) return load ? 'ldrb' : 'strb';
    if (size === 1) return load ? 'ldrh' : 'strh';
    return load ? 'ldr' : 'str';
}

function loadStoreRegPrefix(size) {
    return size === 3 ? 'x' : 'w';
}

function decodeLoadStoreSigned(value) {
    let size = (value >>> 30) & 3;
    let v = (value >>> 26) & 1;
    let opc = (value >>> 22) & 3;
    if (v) return null;
    if (size === 3 && (opc & 2)) return null;

    let mode = (value >>> 10) & 3;
    if (![0, 1, 3].includes(mode)) return null;

    let imm9 = signExtend((value >>> 12) & 0x1ff, 9);
    let rn = (value >>> 5) & 0x1f;
    let rt = value & 0x1f;
    let rnReg = rn === 31 ? 'sp' : `x${rn}`;
    let offsetPart = imm9 ? `, ${immStr(imm9)}` : '';

    if (opc & 2) {

        const names = { 0: 'ldrsb', 1: 'ldrsh', 2: 'ldrsw' };
        let baseMnemonic = names[size];
        if (!baseMnemonic) return null;
        let rtReg = opc === 2 ? `x${rt}` : `w${rt}`;
        if (mode === 1) return `${baseMnemonic} ${rtReg}, [${rnReg}], ${immStr(imm9)}`;
        if (mode === 3) return `${baseMnemonic} ${rtReg}, [${rnReg}, ${immStr(imm9)}]!`;
        let unscaledMnemonic = 'ldur' + baseMnemonic.slice(3);
        return `${unscaledMnemonic} ${rtReg}, [${rnReg}${offsetPart}]`;
    }

    let load = (opc & 1) === 1;
    let mnemonic = loadStoreMnemonic(load, size);
    let rtReg = reg(loadStoreRegPrefix(size), rt);

    if (mode === 1) return `${mnemonic} ${rtReg}, [${rnReg}], ${immStr(imm9)}`;
    if (mode === 3) return `${mnemonic} ${rtReg}, [${rnReg}, ${immStr(imm9)}]!`;
    let unscaledMnemonic = mnemonic.replace(/r(b|h)?$/, 'ur$1');
    return `${unscaledMnemonic} ${rtReg}, [${rnReg}${imm9 ? `, ${immStr(imm9)}` : ''}]`;
}

function decodeLoadStoreRegOffset(value) {
    if (!matches(value, 0x3f200c00, 0x38200800)) return null;
    let size = (value >>> 30) & 3, opc = (value >>> 22) & 3;
    let rm = (value >>> 16) & 0x1f, option = (value >>> 13) & 7;
    let s = (value >>> 12) & 1, rn = (value >>> 5) & 0x1f, rt = value & 0x1f;
    if (option !== 2 && option !== 3 && option !== 6 && option !== 7) return null;
    const names = {
        3: ['str', 'ldr', 'prfm', null],
        2: ['str', 'ldr', 'ldrsw', null],
        1: ['strh', 'ldrh', 'ldrsh', 'ldrsh'],
        0: ['strb', 'ldrb', 'ldrsb', 'ldrsb']
    };
    let mnemonic = names[size][opc];
    if (!mnemonic) return null;
    let rtSize = size === 3 ? 64 : size === 2 ? 32 : (opc === 3 ? 32 : opc === 2 ? 64 : 32);
    let rnReg = rn === 31 ? 'sp' : `x${rn}`;
    let shiftAmt = s ? size : 0;
    const extMap = { 2: 'uxtw', 3: 'lsl', 6: 'sxtw', 7: 'sxtx' };
    let ext = extMap[option];
    let rmReg = (option === 2 || option === 6) ? `w${rm}` : `x${rm}`;
    let extPart;
    if (option === 3) {
        extPart = s ? `, lsl #${shiftAmt}` : '';
    } else {
        extPart = s ? `, ${ext} #${shiftAmt}` : `, ${ext}`;
    }
    return `${mnemonic} ${reg(rtSize === 64 ? 'x' : 'w', rt)}, [${rnReg}, ${rmReg}${extPart}]`;
}

function decodeLoadStorePairSimd(value) {
    if (!matches(value, 0x3e000000, 0x2c000000)) return null;
    let opcSize = (value >>> 30) & 3;
    if (opcSize === 3) return null;
    let mode = (value >>> 23) & 3, l = (value >>> 22) & 1;
    if (mode === 0) return null;
    let scale = opcSize === 0 ? 2 : opcSize === 1 ? 3 : 4;
    let imm7 = signExtend((value >>> 15) & 0x7f, 7) << scale;
    let rt2 = (value >>> 10) & 0x1f, rn = (value >>> 5) & 0x1f, rt = value & 0x1f;
    let p = opcSize === 0 ? 's' : opcSize === 1 ? 'd' : 'q';
    let rnReg = rn === 31 ? 'sp' : `x${rn}`;
    let mnemonic = l ? 'ldp' : 'stp';
    let addr = mode === 1 ? `[${rnReg}], ${immStr(imm7)}`
        : mode === 3 ? `[${rnReg}, ${immStr(imm7)}]!`
            : `[${rnReg}${imm7 ? `, ${immStr(imm7)}` : ''}]`;
    return `${mnemonic} ${p}${rt}, ${p}${rt2}, ${addr}`;
}

const condNames = ['eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv'];

function decodeCondSelect(value) {
    if (!matches(value, 0x1fe00000, 0x1a800000)) return null;
    let sf = (value >>> 31) & 1, op = (value >>> 30) & 1;
    let rm = (value >>> 16) & 0x1f, cond = (value >>> 12) & 0xf, op2 = (value >>> 10) & 3;
    if (op2 & 2) return null;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f, p = sf ? 'x' : 'w';
    const names = { '0-0': 'csel', '0-1': 'csinc', '1-0': 'csinv', '1-1': 'csneg' };
    let name = names[`${op}-${op2 & 1}`];
    if (name !== 'csel' && rm === rn && rm === 31 && cond < 14) {
        let inv = condNames[cond ^ 1];
        if (name === 'csinc') return `cset ${reg(p, rd)}, ${inv}`;
        if (name === 'csinv') return `csetm ${reg(p, rd)}, ${inv}`;
    }

    if (name !== 'csel' && name !== 'csneg' && rm === rn && rd !== 31 && cond < 14) {
        let inv = condNames[cond ^ 1];
        let alias = name === 'csinc' ? 'cinc' : 'cinv';
        return `${alias} ${p}${rd}, ${reg(p, rn)}, ${inv}`;
    }
    if (name === 'csneg' && rm === rn && rd !== 31 && cond < 14) {
        let inv = condNames[cond ^ 1];
        return `cneg ${p}${rd}, ${reg(p, rn)}, ${inv}`;
    }
    return `${name} ${p}${rd}, ${reg(p, rn)}, ${reg(p, rm)}, ${condNames[cond]}`;
}

function decodeCondCompare(value) {
    if (!matches(value, 0x3fe00400, 0x3a400000)) return null;
    let sf = (value >>> 31) & 1, op = (value >>> 30) & 1;
    let imm = (value >>> 11) & 1, y = (value >>> 16) & 0x1f;
    let cond = (value >>> 12) & 0xf, rn = (value >>> 5) & 0x1f, nzcv = value & 0xf;
    let p = sf ? 'x' : 'w';
    let src = imm ? immStr(y) : reg(p, y);
    return `${op ? 'ccmp' : 'ccmn'} ${reg(p, rn)}, ${src}, #${nzcv}, ${condNames[cond]}`;
}

function decodeAtomic(value) {

    if (matches(value, 0x3f208c00, 0x38200000)) {
        let size = (value >>> 30) & 3;
        let a = (value >>> 23) & 1, r = (value >>> 22) & 1;
        let rs = (value >>> 16) & 0x1f, opc = (value >>> 12) & 7;
        let rn = (value >>> 5) & 0x1f, rt = value & 0x1f;
        let p = size === 3 ? 'x' : size === 2 ? 'w' : size === 1 ? 'w' : 'w';
        let names = { 0: 'ldadd', 1: 'ldclr', 2: 'ldeor', 3: 'ldset', 4: 'ldsmax', 5: 'ldsmin', 6: 'ldumax', 7: 'ldumin' };
        let name = names[opc];
        let suffix = (a && r) ? 'al' : a ? 'a' : r ? 'l' : '';
        let sizeSuf = size === 0 ? 'b' : size === 1 ? 'h' : '';
        let rnReg = rn === 31 ? 'sp' : `x${rn}`;

        return `${name}${suffix}${sizeSuf} ${reg(p, rs)}, ${reg(p, rt)}, [${rnReg}]`;
    }

    if (matches(value, 0x3ffffc00, 0x38bfc000)) {
        let size = (value >>> 30) & 3;
        let rn = (value >>> 5) & 0x1f, rt = value & 0x1f;
        let p = size === 3 ? 'x' : 'w';
        let sizeSuf = size === 0 ? 'b' : size === 1 ? 'h' : '';
        let rnReg = rn === 31 ? 'sp' : `x${rn}`;
        return `ldapr${sizeSuf} ${reg(p, rt)}, [${rnReg}]`;
    }
    return null;
}

function decodeSwp(value) {

    if (!matches(value, 0x3f20fc00, 0x38208000)) return null;
    let size = (value >>> 30) & 3;
    let a = (value >>> 23) & 1, r = (value >>> 22) & 1;
    let rs = (value >>> 16) & 0x1f, rn = (value >>> 5) & 0x1f, rt = value & 0x1f;
    let p = size === 3 ? 'x' : 'w';
    let sizeSuf = size === 0 ? 'b' : size === 1 ? 'h' : '';
    let suffix = (a && r) ? 'al' : a ? 'a' : r ? 'l' : '';
    let rnReg = rn === 31 ? 'sp' : `x${rn}`;
    return `swp${suffix}${sizeSuf} ${reg(p, rs)}, ${reg(p, rt)}, [${rnReg}]`;
}

function decodeCas(value) {

    if (!matches(value, 0x3fa07c00, 0x08a07c00)) return null;
    let size = (value >>> 30) & 3;
    let l = (value >>> 22) & 1, o0 = (value >>> 15) & 1;
    let rs = (value >>> 16) & 0x1f, rn = (value >>> 5) & 0x1f, rt = value & 0x1f;
    let p = size === 3 ? 'x' : size === 2 ? 'w' : 'w';
    let sizeSuf = size === 0 ? 'b' : size === 1 ? 'h' : '';
    let suffix = (l && o0) ? 'al' : l ? 'a' : o0 ? 'l' : '';
    let rnReg = rn === 31 ? 'sp' : `x${rn}`;
    return `cas${suffix}${sizeSuf} ${reg(p, rs)}, ${reg(p, rt)}, [${rnReg}]`;
}

function decodeCrc32(value) {
    if (!matches(value, 0x7fe0e000, 0x1ac04000)) return null;
    let rm = (value >>> 16) & 0x1f;
    let c = (value >>> 12) & 1, sz = (value >>> 10) & 3;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;

    let sf = (value >>> 31) & 1;
    if ((sz === 3) !== (sf === 1)) return null;
    let name = c ? 'crc32c' : 'crc32';
    let suf = ['b', 'h', 'w', 'x'][sz];
    let rmReg = sz === 3 ? `x${rm}` : `w${rm}`;
    return `${name}${suf} w${rd}, w${rn}, ${rmReg}`;
}

const barrierOpts = {
    15: 'sy', 14: 'st', 13: 'ld', 11: 'ish', 10: 'ishst', 9: 'ishld',
    7: 'nsh', 6: 'nshst', 5: 'nshld', 3: 'osh', 2: 'oshst', 1: 'oshld'
};
function decodeBarrier(value) {
    if (matches(value, 0xfffff0ff, 0xd503309f)) {
        let crm = (value >>> 8) & 0xf;
        return `dsb ${barrierOpts[crm] || `#${crm}`}`;
    }
    if (matches(value, 0xfffff0ff, 0xd50330bf)) {
        let crm = (value >>> 8) & 0xf;
        return `dmb ${barrierOpts[crm] || `#${crm}`}`;
    }
    if (matches(value, 0xfffff0ff, 0xd50330df)) {
        return 'isb';
    }
    if (matches(value, 0xfffff0ff, 0xd503305f)) {
        let crm = (value >>> 8) & 0xf;
        return crm === 0xf ? 'clrex' : `clrex #${crm}`;
    }
    return null;
}

const dcOps = {
    'ivac': [0, 7, 6, 1], 'isw': [0, 7, 6, 2], 'csw': [0, 7, 10, 2], 'cisw': [0, 7, 14, 2],
    'zva': [3, 7, 4, 1], 'cvac': [3, 7, 10, 1], 'cvau': [3, 7, 11, 1], 'civac': [3, 7, 14, 1],
    'cvap': [3, 7, 12, 1], 'cvadp': [3, 7, 13, 1],
};
const icOps = {
    'ialluis': [0, 7, 1, 0, false], 'iallu': [0, 7, 5, 0, false], 'ivau': [3, 7, 5, 1, true],
};
function decodeDcIc(value) {
    if (!matches(value, 0xfff80000, 0xd5080000)) return null;
    let op1 = (value >>> 16) & 7, CRn = (value >>> 12) & 0xf, CRm = (value >>> 8) & 0xf;
    let op2 = (value >>> 5) & 7, Rt = value & 0x1f;
    if (CRn !== 7) return null;
    for (const [name, [o1, crn, crm, o2]] of Object.entries(dcOps)) {
        if (op1 === o1 && CRm === crm && op2 === o2) return `dc ${name}, x${Rt}`;
    }
    for (const [name, [o1, crn, crm, o2, hasRt]] of Object.entries(icOps)) {
        if (op1 === o1 && CRm === crm && op2 === o2) {
            return hasRt ? `ic ${name}, x${Rt}` : `ic ${name}`;
        }
    }
    return null;
}

function encDcIc(mnemonic, ops) {
    let opName = ops[0].toLowerCase();
    let table = mnemonic === 'dc' ? dcOps : icOps;
    if (!(opName in table)) throw new Error(`Unknown ${mnemonic} operation: ${opName}`);
    let [op1, CRn, CRm, op2, hasRt] = table[opName];
    let hasReg = mnemonic === 'dc' ? true : hasRt;
    let Rt = 31;
    if (hasReg) {
        if (!ops[1]) throw new Error(`${mnemonic} ${opName} requires a register operand`);
        Rt = parseReg(ops[1]).num;
    }
    return (0xd5080000 | (op1 << 16) | (CRn << 12) | (CRm << 8) | (op2 << 5) | Rt) >>> 0;
}
function decodeMsrImm(value) {

    if (!matches(value, 0xfff8f01f, 0xd500401f)) return null;
    let op1 = (value >>> 16) & 7, op2 = (value >>> 5) & 7;
    const pstates = { '0-5': 'spsel', '3-6': 'daifset', '3-7': 'daifclr' };
    let key = `${op1}-${op2}`;
    let name = pstates[key];
    let crm = (value >>> 8) & 0xf;
    if (!name) return null;
    return `msr ${name}, #${crm}`;
}

function decodeFmov(value) {

    if (matches(value, 0x7f3ffc00, 0x1e204000)) {
        let type = (value >>> 22) & 3;
        let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
        let p = type === 1 ? 'd' : type === 3 ? 'h' : 's';
        return `fmov ${p}${rd}, ${p}${rn}`;
    }

    if (matches(value, 0x7f3ffc00, 0x1e260000) || matches(value, 0x7f3ffc00, 0x1e270000) ||
        matches(value, 0x7f3ffc00, 0x9e660000) || matches(value, 0x7f3ffc00, 0x9e670000) ||
        matches(value, 0x7f3ffc00, 0x9eae0000) || matches(value, 0x7f3ffc00, 0x9eaf0000)) {
        let sf = (value >>> 31) & 1, type = (value >>> 22) & 3;
        let rmode = (value >>> 19) & 3, opcode = (value >>> 16) & 7;
        let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
        if (type === 0 && rmode === 0 && opcode === 6) return `fmov w${rd}, s${rn}`;
        if (type === 0 && rmode === 0 && opcode === 7) return `fmov s${rd}, ${reg('w', rn)}`;
        if (type === 1 && rmode === 0 && opcode === 6) return `fmov x${rd}, d${rn}`;
        if (type === 1 && rmode === 0 && opcode === 7) return `fmov d${rd}, ${reg('x', rn)}`;
        if (type === 2 && rmode === 1 && opcode === 6) return `fmov x${rd}, v${rn}.d[1]`;
        if (type === 2 && rmode === 1 && opcode === 7) return `fmov v${rd}.d[1], ${reg('x', rn)}`;
    }
    return null;
}

function decodeLoadStoreSimdUnsigned(value) {
    if (!matches(value, 0x3f000000, 0x3d000000)) return null;
    let size = (value >>> 30) & 3, opc = (value >>> 22) & 3;
    let imm12 = (value >>> 10) & 0xfff, rn = (value >>> 5) & 0x1f, rt = value & 0x1f;
    let p, scale, load;
    if (size === 0 && (opc & 2)) { p = 'q'; scale = 4; load = (opc === 3); }
    else if (size === 0) { p = 'b'; scale = 0; load = (opc === 1); }
    else if (size === 1) { p = 'h'; scale = 1; load = (opc === 1); }
    else if (size === 2) { p = 's'; scale = 2; load = (opc === 1); }
    else if (size === 3) { p = 'd'; scale = 3; load = (opc === 1); }
    else return null;
    if (size === 0 && !(opc === 0 || opc === 1 || opc === 2 || opc === 3)) return null;
    let offset = imm12 << scale;
    let rnReg = rn === 31 ? 'sp' : `x${rn}`;
    let addr = offset ? `[${rnReg}, #${offset}]` : `[${rnReg}]`;
    return `${load ? 'ldr' : 'str'} ${p}${rt}, ${addr}`;
}

function decodeLoadStoreSimdUnscaled(value) {
    if (!matches(value, 0x3f200000, 0x3c000000)) return null;
    let size = (value >>> 30) & 3, opc = (value >>> 22) & 3;
    let mode = (value >>> 10) & 3;
    if (![0, 1, 3].includes(mode)) return null;
    let imm9 = signExtend((value >>> 12) & 0x1ff, 9);
    let rn = (value >>> 5) & 0x1f, rt = value & 0x1f;
    let p, load;
    if (size === 0 && (opc & 2)) { p = 'q'; load = (opc === 3); }
    else if (size === 0) { p = 'b'; load = (opc === 1); }
    else if (size === 1) { p = 'h'; load = (opc === 1); }
    else if (size === 2) { p = 's'; load = (opc === 1); }
    else if (size === 3) { p = 'd'; load = (opc === 1); }
    else return null;
    let mnemonic = (mode === 0) ? (load ? 'ldur' : 'stur') : (load ? 'ldr' : 'str');
    let rnReg = rn === 31 ? 'sp' : `x${rn}`;
    let rtReg = `${p}${rt}`;
    if (mode === 1) return `${mnemonic} ${rtReg}, [${rnReg}], ${immStr(imm9)}`;
    if (mode === 3) return `${mnemonic} ${rtReg}, [${rnReg}, ${immStr(imm9)}]!`;
    return `${mnemonic} ${rtReg}, [${rnReg}${imm9 ? `, ${immStr(imm9)}` : ''}]`;
}

function decodeLoadStoreSimdRegOffset(value) {
    if (!matches(value, 0x3f200c00, 0x3c200800)) return null;
    let size = (value >>> 30) & 3, opc = (value >>> 22) & 3;
    let rm = (value >>> 16) & 0x1f, option = (value >>> 13) & 7, s = (value >>> 12) & 1;
    let rn = (value >>> 5) & 0x1f, rt = value & 0x1f;
    if (option !== 2 && option !== 3 && option !== 6 && option !== 7) return null;
    let p, load, shiftAmt;
    if (size === 0 && (opc & 2)) { p = 'q'; load = (opc === 3); shiftAmt = 4; }
    else if (size === 0) { p = 'b'; load = (opc === 1); shiftAmt = 0; }
    else if (size === 1) { p = 'h'; load = (opc === 1); shiftAmt = 1; }
    else if (size === 2) { p = 's'; load = (opc === 1); shiftAmt = 2; }
    else if (size === 3) { p = 'd'; load = (opc === 1); shiftAmt = 3; }
    else return null;
    let rnReg = rn === 31 ? 'sp' : `x${rn}`;
    const extMap = { 2: 'uxtw', 3: 'lsl', 6: 'sxtw', 7: 'sxtx' };
    let ext = extMap[option];
    let rmReg = (option === 2 || option === 6) ? `w${rm}` : `x${rm}`;
    let extPart = (option === 3) ? (s ? `, lsl #${shiftAmt}` : '') : (s ? `, ${ext} #${shiftAmt}` : `, ${ext}`);
    return `${load ? 'ldr' : 'str'} ${p}${rt}, [${rnReg}, ${rmReg}${extPart}]`;
}

function decodeLoadLiteralSimd(value) {
    if (!matches(value, 0x3f000000, 0x1c000000)) return null;
    let opc = (value >>> 30) & 3;
    if (opc === 3) return null;
    let p = opc === 0 ? 's' : opc === 1 ? 'd' : 'q';
    let imm19 = signExtend((value >>> 5) & 0x7ffff, 19) << 2;
    let rt = value & 0x1f;
    return `ldr ${p}${rt}, ${immStr(imm19)}`;
}

const FP_PREFIX_MASK = 0xff200000, FP_PREFIX_VAL = 0x1e200000;
const fpTypeSuffix = { 0: 's', 1: 'd', 3: 'h' };

function decodeFp2Source(value) {

    if (!matches(value, 0xff200c00, 0x1e200800)) return null;
    let type = (value >>> 22) & 3, rm = (value >>> 16) & 0x1f;
    let opcode = (value >>> 12) & 0xf, rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    const names = { 0: 'fmul', 1: 'fdiv', 2: 'fadd', 3: 'fsub', 4: 'fmax', 5: 'fmin', 6: 'fmaxnm', 7: 'fminnm', 8: 'fnmul' };
    let name = names[opcode];
    let p = fpTypeSuffix[type];
    if (!name || !p) return null;
    return `${name} ${p}${rd}, ${p}${rn}, ${p}${rm}`;
}

function decodeFpCompare(value) {

    if (!matches(value, 0xff20fc00, 0x1e202000)) return null;
    let type = (value >>> 22) & 3, rm = (value >>> 16) & 0x1f;
    let rn = (value >>> 5) & 0x1f, opcode2 = value & 0x1f;
    let p = fpTypeSuffix[type];
    if (!p) return null;
    let name = (opcode2 & 0x10) ? 'fcmpe' : 'fcmp';
    if ((opcode2 & 0x8)) return `${name} ${p}${rn}, #0.0`;
    return `${name} ${p}${rn}, ${p}${rm}`;
}

function decodeFpConvertFixed(value) {
    if ((value >>> 30) & 1) return null;
    if ((value >>> 29) & 1) return null;
    if (((value >>> 24) & 0x1f) !== 0x1e) return null;
    if ((value >>> 21) & 1) return null;

    let sf = (value >>> 31) & 1, type = (value >>> 22) & 3;
    let rmode = (value >>> 19) & 3, opcode = (value >>> 16) & 7;
    let scale = (value >>> 10) & 0x3f, rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let p = fpTypeSuffix[type];
    if (!p) return null;
    let intReg = sf ? 'x' : 'w';
    let fbits = 64 - scale;
    if (fbits < 1 || fbits > (sf ? 64 : 32)) return null;

    if (rmode === 0 && (opcode === 2 || opcode === 3)) {
        let name = opcode === 2 ? 'scvtf' : 'ucvtf';
        return `${name} ${p}${rd}, ${reg(intReg, rn)}, #${fbits}`;
    }
    if (rmode === 3 && (opcode === 0 || opcode === 1)) {
        let name = opcode === 0 ? 'fcvtzs' : 'fcvtzu';
        return `${name} ${reg(intReg, rd)}, ${p}${rn}, #${fbits}`;
    }
    return null;
}

function decodeFpConvertIntFp(value) {

    if (!matches(value, 0x7f20fc00, 0x1e200000)) return null;
    let sf = (value >>> 31) & 1, type = (value >>> 22) & 3;
    let rmode = (value >>> 19) & 3, opcode = (value >>> 16) & 7;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let p = fpTypeSuffix[type];
    if (!p) return null;
    let intReg = sf ? 'x' : 'w';
    const table = {
        '00-0': 'fcvtns', '00-1': 'fcvtnu',
        '01-0': 'fcvtps', '01-1': 'fcvtpu',
        '10-0': 'fcvtms', '10-1': 'fcvtmu',
        '11-0': 'fcvtzs', '11-1': 'fcvtzu'
    };
    if (opcode === 2 || opcode === 3) {
        let name = opcode === 2 ? 'scvtf' : 'ucvtf';
        return `${name} ${p}${rd}, ${reg(intReg, rn)}`;
    }
    if (opcode === 4 || opcode === 5) {
        let name = opcode === 4 ? 'fcvtas' : 'fcvtau';
        return `${name} ${reg(intReg, rd)}, ${p}${rn}`;
    }
    if (opcode === 0 || opcode === 1) {
        let key = `${rmode === 3 ? '11' : rmode === 1 ? '01' : rmode === 2 ? '10' : '00'}-${opcode}`;
        let name = table[key];
        if (!name) return null;
        return `${name} ${reg(intReg, rd)}, ${p}${rn}`;
    }
    return null;
}

function decodeFp1Source(value) {

    if (!matches(value, 0xff207c00, 0x1e204000)) return null;
    let type = (value >>> 22) & 3, opcode = (value >>> 15) & 0x3f;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let p = fpTypeSuffix[type];
    if (!p) return null;
    if (opcode === 0) return null;
    const unary = {
        1: 'fabs', 2: 'fneg', 3: 'fsqrt', 8: 'frintn', 9: 'frintp',
        10: 'frintm', 11: 'frintz', 12: 'frinta', 14: 'frintx', 15: 'frinti'
    };
    if (unary[opcode]) return `${unary[opcode]} ${p}${rd}, ${p}${rn}`;
    if (opcode === 4 || opcode === 5 || opcode === 7) {
        let dstP = opcode === 4 ? 's' : opcode === 5 ? 'd' : 'h';
        if (dstP === p) return null;
        return `fcvt ${dstP}${rd}, ${p}${rn}`;
    }
    return null;
}

function decodeFcCmp(value) {

    if (!matches(value, 0xff200c10, 0x1e200400)) return null;
    let type = (value >>> 22) & 3, rm = (value >>> 16) & 0x1f;
    let cond = (value >>> 12) & 0xf, rn = (value >>> 5) & 0x1f;
    let op = (value >>> 4) & 1, nzcv = value & 0xf;
    let p = fpTypeSuffix[type];
    if (!p) return null;
    return `${op ? 'fccmpe' : 'fccmp'} ${p}${rn}, ${p}${rm}, #${nzcv}, ${condNames[cond]}`;
}

function decodeFcSel(value) {

    if (!matches(value, 0xff200c00, 0x1e200c00)) return null;
    let type = (value >>> 22) & 3, rm = (value >>> 16) & 0x1f;
    let cond = (value >>> 12) & 0xf, rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let p = fpTypeSuffix[type];
    if (!p) return null;
    return `fcsel ${p}${rd}, ${p}${rn}, ${p}${rm}, ${condNames[cond]}`;
}

function fpImm8ToFloat(imm8, isDouble) {
    let sign = (imm8 >>> 7) & 1;
    let b = (imm8 >>> 6) & 1;
    let cd = (imm8 >>> 4) & 3;
    let efgh = imm8 & 0xf;
    let notB = b ? 0 : 1;
    let buf = new ArrayBuffer(8);
    let view = new DataView(buf);
    if (isDouble) {

        let expBits = (notB << 10) | (b ? 0x3fc : 0) | cd;
        let hi = (sign << 31) | (expBits << 20) | (efgh << 16);
        view.setUint32(0, hi >>> 0, false);
        view.setUint32(4, 0, false);
        return view.getFloat64(0, false);
    } else {

        let expBits = (notB << 7) | (b ? 0x7c : 0) | cd;
        let word = (sign << 31) | (expBits << 23) | (efgh << 19);
        view.setUint32(0, word >>> 0, false);
        return view.getFloat32(0, false);
    }
}

function formatFpImm(n) {
    return n.toFixed(8);
}

function decodeFpImmediate(value) {

    if (!matches(value, 0xff201fe0, 0x1e201000)) return null;
    let type = (value >>> 22) & 3, imm8 = (value >>> 13) & 0xff, rd = value & 0x1f;
    let p = fpTypeSuffix[type];
    if (!p || p === 'h') return null;
    let isDouble = p === 'd';
    let n = fpImm8ToFloat(imm8, isDouble);
    return `fmov ${p}${rd}, #${formatFpImm(n)}`;
}

function decodeFp3Source(value) {

    if (!matches(value, 0xff000000, 0x1f000000)) return null;
    let type = (value >>> 22) & 3, o1 = (value >>> 21) & 1, rm = (value >>> 16) & 0x1f;
    let o0 = (value >>> 15) & 1, ra = (value >>> 10) & 0x1f;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let p = fpTypeSuffix[type];
    if (!p) return null;
    const names = { '0-0': 'fmadd', '0-1': 'fmsub', '1-0': 'fnmadd', '1-1': 'fnmsub' };
    let name = names[`${o1}-${o0}`];
    if (!name) return null;
    return `${name} ${p}${rd}, ${p}${rn}, ${p}${rm}, ${p}${ra}`;
}

function highestSetBit(x, width) {
    for (let i = width - 1; i >= 0; i--) if ((x >> BigInt(i)) & 1n) return i;
    return -1;
}

function decodeBitMasks(N, immr, imms, is64) {
    let width = is64 ? 64 : 32;
    let combined = (BigInt(N) << 6n) | BigInt((~imms) & 0x3f);
    let len = highestSetBit(combined, 7);
    if (len < 1) return null;
    let size = 1 << len;
    let levels = BigInt(size - 1);
    let S = BigInt(imms) & levels;
    let R = BigInt(immr) & levels;
    if (S === levels) return null;

    let welem = (1n << (S + 1n)) - 1n;

    let sizeBig = BigInt(size);
    let rot = R % sizeBig;
    let wpattern = ((welem >> rot) | (welem << (sizeBig - rot))) & ((1n << sizeBig) - 1n);

    let result = 0n;
    for (let i = 0; i < width / size; i++) {
        result |= wpattern << BigInt(i * size);
    }
    let mask = (1n << BigInt(width)) - 1n;
    return result & mask;
}

function bigIntToImmStr(n, is64) {
    return '#' + n.toString(10);
}

function decodeLogicalImm(value) {

    if (!matches(value, 0x1f800000, 0x12000000)) return null;
    let sf = (value >>> 31) & 1, opc = (value >>> 29) & 3;
    let N = (value >>> 22) & 1, immr = (value >>> 16) & 0x3f, imms = (value >>> 10) & 0x3f;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    if (!sf && N) return null;
    let is64 = sf === 1;
    let bits = decodeBitMasks(N, immr, imms, is64);
    if (bits === null) return null;
    const names = { 0: 'and', 1: 'orr', 2: 'eor', 3: 'ands' };
    let name = names[opc];
    let p = is64 ? 'x' : 'w';
    let rdReg = (opc === 3) ? reg(p, rd) : (rd === 31 ? (is64 ? 'sp' : 'wsp') : `${p}${rd}`);
    let immStrVal = bigIntToImmStr(bits, is64);

    if (opc === 3 && rd === 31) return `tst ${reg(p, rn)}, ${immStrVal}`;
    if (opc === 1 && rn === 31 && rd !== 31) {
        let width = is64 ? 64n : 32n;
        let signedVal = bits >= (1n << (width - 1n)) ? bits - (1n << width) : bits;
        return `mov ${reg(p, rd)}, #${signedVal.toString(10)}`;
    }
    return `${name} ${rdReg}, ${reg(p, rn)}, ${immStrVal}`;
}

function decodeBitfield(value) {

    if (!matches(value, 0x1f800000, 0x13000000)) return null;
    let sf = (value >>> 31) & 1, opc = (value >>> 29) & 3;
    let N = (value >>> 22) & 1, immr = (value >>> 16) & 0x3f, imms = (value >>> 10) & 0x3f;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let is64 = sf === 1;
    if (N !== (is64 ? 1 : 0)) return null;
    let p = is64 ? 'x' : 'w';
    let regSize = is64 ? 64 : 32;

    if (opc === 0) {
        if (imms === regSize - 1) return `asr ${reg(p, rd)}, ${reg(p, rn)}, #${immr}`;
        if (immr === 0 && imms === 7) return `sxtb ${reg(p, rd)}, ${reg('w', rn)}`;
        if (immr === 0 && imms === 15) return `sxth ${reg(p, rd)}, ${reg('w', rn)}`;
        if (immr === 0 && imms === 31 && is64) return `sxtw ${reg(p, rd)}, ${reg('w', rn)}`;
        if (imms < immr) {
            let lsb = (regSize - immr) % regSize, width = imms + 1;
            return `sbfiz ${reg(p, rd)}, ${reg(p, rn)}, #${lsb}, #${width}`;
        }
        let lsb = immr, width = imms - immr + 1;
        return `sbfx ${reg(p, rd)}, ${reg(p, rn)}, #${lsb}, #${width}`;
    }
    if (opc === 2) {
        if (immr === 0 && imms === regSize - 1) return `mov ${reg(p, rd)}, ${reg(p, rn)}`;
        if (imms + 1 === immr) return `lsl ${reg(p, rd)}, ${reg(p, rn)}, #${regSize - immr}`;
        if (imms === regSize - 1) return `lsr ${reg(p, rd)}, ${reg(p, rn)}, #${immr}`;
        if (immr === 0 && imms === 7) return `uxtb ${reg('w', rd)}, ${reg('w', rn)}`;
        if (immr === 0 && imms === 15) return `uxth ${reg('w', rd)}, ${reg('w', rn)}`;
        if (imms < immr) {
            let lsb = (regSize - immr) % regSize, width = imms + 1;
            return `ubfiz ${reg(p, rd)}, ${reg(p, rn)}, #${lsb}, #${width}`;
        }
        let lsb = immr, width = imms - immr + 1;
        return `ubfx ${reg(p, rd)}, ${reg(p, rn)}, #${lsb}, #${width}`;
    }
    if (opc === 1) {
        if (rn === 31 && imms < immr) {
            let lsb = (regSize - immr) % regSize, width = imms + 1;
            return `bfc ${reg(p, rd)}, #${lsb}, #${width}`;
        }
        if (imms < immr) {
            let lsb = (regSize - immr) % regSize, width = imms + 1;
            return `bfi ${reg(p, rd)}, ${reg(p, rn)}, #${lsb}, #${width}`;
        }
        let lsb = immr, width = imms - immr + 1;
        return `bfxil ${reg(p, rd)}, ${reg(p, rn)}, #${lsb}, #${width}`;
    }
    return null;
}

function decodeDataProc3Source(value) {

    if (!matches(value, 0x7f000000, 0x1b000000)) return null;
    let sf = (value >>> 31) & 1, op31 = (value >>> 21) & 7;
    let rm = (value >>> 16) & 0x1f, o0 = (value >>> 15) & 1;
    let ra = (value >>> 10) & 0x1f, rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let p = sf ? 'x' : 'w';

    if (op31 === 0) {
        if (o0 === 0) {
            if (ra === 31) return `mul ${p}${rd}, ${reg(p, rn)}, ${reg(p, rm)}`;
            return `madd ${p}${rd}, ${reg(p, rn)}, ${reg(p, rm)}, ${reg(p, ra)}`;
        } else {
            if (ra === 31) return `mneg ${p}${rd}, ${reg(p, rn)}, ${reg(p, rm)}`;
            return `msub ${p}${rd}, ${reg(p, rn)}, ${reg(p, rm)}, ${reg(p, ra)}`;
        }
    }
    if (!sf) return null;
    if (op31 === 1) {
        if (o0 === 0) {
            if (ra === 31) return `smull x${rd}, ${reg('w', rn)}, ${reg('w', rm)}`;
            return `smaddl x${rd}, ${reg('w', rn)}, ${reg('w', rm)}, x${ra}`;
        } else {
            if (ra === 31) return `smnegl x${rd}, ${reg('w', rn)}, ${reg('w', rm)}`;
            return `smsubl x${rd}, ${reg('w', rn)}, ${reg('w', rm)}, x${ra}`;
        }
    }
    if (op31 === 2 && o0 === 0 && ra === 31) return `smulh x${rd}, x${rn}, x${rm}`;
    if (op31 === 5) {
        if (o0 === 0) {
            if (ra === 31) return `umull x${rd}, ${reg('w', rn)}, ${reg('w', rm)}`;
            return `umaddl x${rd}, ${reg('w', rn)}, ${reg('w', rm)}, x${ra}`;
        } else {
            if (ra === 31) return `umnegl x${rd}, ${reg('w', rn)}, ${reg('w', rm)}`;
            return `umsubl x${rd}, ${reg('w', rn)}, ${reg('w', rm)}, x${ra}`;
        }
    }
    if (op31 === 6 && o0 === 0 && ra === 31) return `umulh x${rd}, x${rn}, x${rm}`;
    return null;
}

function decodeBrk(value) {
    if (!matches(value, 0xffe0001f, 0xd4200000)) return null;
    let imm16 = (value >>> 5) & 0xffff;
    return `brk #${imm16}`;
}

function decodeDataProc1SourceBit(value) {
    if (!matches(value, 0x7fff0000, 0x5ac00000)) return null;
    let sf = (value >>> 31) & 1, opcode = (value >>> 10) & 0x3f;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let p = sf ? 'x' : 'w';
    if (opcode === 3 && !sf) return null;
    const names = { 0: 'rbit', 1: 'rev16', 2: sf ? 'rev32' : 'rev', 3: 'rev', 4: 'clz', 5: 'cls' };
    let name = names[opcode];
    if (!name) return null;
    return `${name} ${p}${rd}, ${reg(p, rn)}`;
}

function decodeLoadStoreExclusive(value) {
    if (!matches(value, 0x3f000000, 0x08000000)) return null;
    let size = (value >>> 30) & 3, o2 = (value >>> 23) & 1, L = (value >>> 22) & 1, o1 = (value >>> 21) & 1;
    let rs = (value >>> 16) & 0x1f, o0 = (value >>> 15) & 1, rt2 = (value >>> 10) & 0x1f;
    let rn = (value >>> 5) & 0x1f, rt = value & 0x1f;
    if (size < 2 && o1 === 1) return null;
    let p = size === 3 ? 'x' : 'w';
    let sizeSuf = size === 0 ? 'b' : size === 1 ? 'h' : '';
    let rnReg = rn === 31 ? 'sp' : `x${rn}`;

    if (o2 === 1 && rs === 31 && rt2 === 31) {

        let name = (L ? (o0 ? 'ldar' : 'ldlar') : (o0 ? 'stlr' : 'stllr')) + sizeSuf;
        return `${name} ${reg(p, rt)}, [${rnReg}]`;
    }
    if (o1 === 0) {
        let name = (L ? (o0 ? 'ldaxr' : 'ldxr') : (o0 ? 'stlxr' : 'stxr')) + sizeSuf;
        if (L) return `${name} ${reg(p, rt)}, [${rnReg}]`;
        return `${name} w${rs}, ${reg(p, rt)}, [${rnReg}]`;
    }

    let name = L ? (o0 ? 'ldaxp' : 'ldxp') : (o0 ? 'stlxp' : 'stxp');
    if (L) return `${name} ${reg(p, rt)}, ${reg(p, rt2)}, [${rnReg}]`;
    return `${name} w${rs}, ${reg(p, rt)}, ${reg(p, rt2)}, [${rnReg}]`;
}

function decodeExtr(value) {
    if (!matches(value, 0x7fa00000, 0x13800000)) return null;
    let sf = (value >>> 31) & 1, N = (value >>> 22) & 1;
    let rm = (value >>> 16) & 0x1f, imms = (value >>> 10) & 0x3f;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    if (N !== sf) return null;
    let p = sf ? 'x' : 'w';
    if (rn === rm) return `ror ${p}${rd}, ${reg(p, rn)}, #${imms}`;
    return `extr ${p}${rd}, ${reg(p, rn)}, ${reg(p, rm)}, #${imms}`;
}

function decodeLogicalShiftedReg(value) {

    if (!matches(value, 0x1f000000, 0x0a000000)) return null;
    let sf = (value >>> 31) & 1, opc = (value >>> 29) & 3;
    let shift = (value >>> 22) & 3, N = (value >>> 21) & 1, rm = (value >>> 16) & 0x1f;
    let imm6 = (value >>> 10) & 0x3f, rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    if (!sf && (imm6 & 0x20)) return null;
    let p = sf ? 'x' : 'w';
    let sh = imm6 ? `, ${['lsl', 'lsr', 'asr', 'ror'][shift]} #${imm6}` : '';
    const baseNames = { 0: 'and', 1: 'orr', 2: 'eor', 3: 'ands' };
    const invNames = { 0: 'bic', 1: 'orn', 2: 'eon', 3: 'bics' };
    let name = N ? invNames[opc] : baseNames[opc];

    if (opc === 1 && !N && rn === 31 && shift === 0 && imm6 === 0) {
        return `mov ${reg(p, rd)}, ${reg(p, rm)}`;
    }
    if (opc === 1 && N && rn === 31) {
        return `mvn ${p}${rd}, ${reg(p, rm)}${sh}`;
    }
    if (opc === 3 && !N && rd === 31) {
        return `tst ${reg(p, rn)}, ${reg(p, rm)}${sh}`;
    }
    return `${name} ${reg(p, rd)}, ${reg(p, rn)}, ${reg(p, rm)}${sh}`;
}

function decodeDataProc2Source(value) {
    if (!matches(value, 0x7fe00000, 0x1ac00000)) return null;
    let sf = (value >>> 31) & 1, rm = (value >>> 16) & 0x1f;
    let opcode = (value >>> 10) & 0x3f, rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let p = sf ? 'x' : 'w';
    const names = { 2: 'udiv', 3: 'sdiv', 8: 'lslv', 9: 'lsrv', 10: 'asrv', 11: 'rorv' };
    const aliasNames = { 8: 'lsl', 9: 'lsr', 10: 'asr', 11: 'ror' };
    if (!(opcode in names)) return null;
    let name = aliasNames[opcode] || names[opcode];
    return `${name} ${p}${rd}, ${reg(p, rn)}, ${reg(p, rm)}`;
}

function decodeAddSubExtended(value) {

    if (!matches(value, 0x1fe00000, 0x0b200000)) return null;
    let sf = (value >>> 31) & 1, op = (value >>> 30) & 1, s = (value >>> 29) & 1;
    let opt = (value >>> 22) & 3;
    if (opt !== 0) return null;
    let rm = (value >>> 16) & 0x1f, option = (value >>> 13) & 7, imm3 = (value >>> 10) & 7;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let p = sf ? 'x' : 'w';
    const extNames = ['uxtb', 'uxth', 'uxtw', 'uxtx', 'sxtb', 'sxth', 'sxtw', 'sxtx'];
    let isNaturalExt = (option === (sf ? 3 : 2));

    let rmReg = (option === 3 || option === 7) ? `x${rm}` : `w${rm}`;
    let usesSpForm = (rd === 31 || rn === 31) && isNaturalExt;
    let extPart;
    if (usesSpForm) {
        extPart = imm3 ? `, lsl #${imm3}` : '';
        rmReg = sf ? `x${rm}` : `w${rm}`;
    } else {
        extPart = imm3 ? `, ${extNames[option]} #${imm3}` : (option === (sf ? 3 : 2) ? '' : `, ${extNames[option]}`);
    }
    let rnReg = rn === 31 ? (sf ? 'sp' : 'wsp') : `${p}${rn}`;
    if (s && rd === 31) {
        return `${op ? 'cmp' : 'cmn'} ${rnReg}, ${rmReg}${extPart}`;
    }
    let rdReg = (s) ? `${p}${rd}` : (rd === 31 ? (sf ? 'sp' : 'wsp') : `${p}${rd}`);
    return `${op ? 'sub' : 'add'}${s ? 's' : ''} ${rdReg}, ${rnReg}, ${rmReg}${extPart}`;
}

function decodeAddSubCarry(value) {
    if (!matches(value, 0x1fe0fc00, 0x1a000000)) return null;
    let sf = (value >>> 31) & 1, op = (value >>> 30) & 1, s = (value >>> 29) & 1;
    let rm = (value >>> 16) & 0x1f, rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let p = sf ? 'x' : 'w';
    if (op && rn === 31) {
        return `${s ? 'ngcs' : 'ngc'} ${p}${rd}, ${reg(p, rm)}`;
    }
    const names = { '0-0': 'adc', '0-1': 'adcs', '1-0': 'sbc', '1-1': 'sbcs' };
    let name = names[`${op}-${s}`];
    return `${name} ${p}${rd}, ${reg(p, rn)}, ${reg(p, rm)}`;
}

function elemInfoFromImm5(imm5) {
    if (imm5 & 1) return { esize: 'b', index: imm5 >>> 1 };
    if (imm5 & 2) return { esize: 'h', index: imm5 >>> 2 };
    if (imm5 & 4) return { esize: 's', index: imm5 >>> 3 };
    if (imm5 & 8) return { esize: 'd', index: imm5 >>> 4 };
    return null;
}

function decodeAdvSimdCopy(value) {
    if ((value >>> 31) & 1) return null;
    if (((value >>> 21) & 0xff) !== 0b01110000) return null;
    if ((value >>> 15) & 1) return null;
    if (!((value >>> 10) & 1)) return null;

    let Q = (value >>> 30) & 1, op = (value >>> 29) & 1;
    let imm5 = (value >>> 16) & 0x1f, imm4 = (value >>> 11) & 0xf;
    let Rn = (value >>> 5) & 0x1f, Rd = value & 0x1f;
    let elem = elemInfoFromImm5(imm5);
    if (!elem) return null;

    if (op === 1) return null;
    if (op === 0 && imm4 === 0) {
        if (!Q && elem.esize === 'd') return null;
        let arr = { b: Q ? '16b' : '8b', h: Q ? '8h' : '4h', s: Q ? '4s' : '2s', d: '2d' }[elem.esize];
        if (elem.esize === 'd' && !Q) return null;
        return `dup v${Rd}.${arr}, v${Rn}.${elem.esize}[${elem.index}]`;
    }
    if (op === 0 && imm4 === 0b0011) {
        return `ins v${Rd}.${elem.esize}[${elem.index}], ${reg(elem.esize === 'd' ? 'x' : 'w', Rn)}`;
    }
    if (op === 0 && imm4 === 0b0101) {

        if (elem.esize === 's' && !Q) return null;
        if (elem.esize === 'd') return null;
        return `smov ${reg(Q ? 'x' : 'w', Rd)}, v${Rn}.${elem.esize}[${elem.index}]`;
    }
    if (op === 0 && imm4 === 0b0111) {

        if (elem.esize === 'd' && !Q) return null;
        if (elem.esize !== 'd' && Q) return null;
        let dst = `${reg(elem.esize === 'd' ? 'x' : 'w', Rd)}, v${Rn}.${elem.esize}[${elem.index}]`;
        let srcBits = { b: 8, h: 16, s: 32, d: 64 }[elem.esize];
        if (srcBits === (elem.esize === 'd' ? 64 : 32)) return `mov ${dst}`;
        return `umov ${dst}`;
    }
    return null;
}

function decodeAdvSimdCopyInsElement(value) {
    if ((value >>> 31) & 1) return null;
    if (((value >>> 30) & 1) !== 1) return null;
    if (((value >>> 29) & 1) !== 1) return null;
    if (((value >>> 21) & 0xff) !== 0b01110000) return null;
    if ((value >>> 15) & 1) return null;
    if (!((value >>> 10) & 1)) return null;

    let imm5 = (value >>> 16) & 0x1f, imm4 = (value >>> 11) & 0xf;
    let Rn = (value >>> 5) & 0x1f, Rd = value & 0x1f;
    let dstElem = elemInfoFromImm5(imm5);
    if (!dstElem) return null;
    const imm5Shift = { b: 1, h: 2, s: 3, d: 4 }[dstElem.esize];
    let srcIndex = imm4 >>> (imm5Shift - 1);
    return `ins v${Rd}.${dstElem.esize}[${dstElem.index}], v${Rn}.${dstElem.esize}[${srcIndex}]`;
}

function decodeAdvSimdScalarCopy(value) {
    if ((value >>> 31) & 1) return null;
    if (((value >>> 30) & 1) !== 1) return null;
    if (((value >>> 29) & 1) !== 0) return null;
    if (((value >>> 21) & 0xff) !== 0b11110000) return null;
    if ((value >>> 15) & 1) return null;
    if (!((value >>> 10) & 1)) return null;
    if (((value >>> 11) & 0xf) !== 0) return null;

    let imm5 = (value >>> 16) & 0x1f;
    let Rn = (value >>> 5) & 0x1f, Rd = value & 0x1f;
    let elem = elemInfoFromImm5(imm5);
    if (!elem) return null;
    return `mov ${elem.esize}${Rd}, v${Rn}.${elem.esize}[${elem.index}]`;
}

function decodeDupGeneral(value) {
    if (!matches(value, 0xbfe0fc00, 0x0e000c00)) return null;
    let Q = (value >>> 30) & 1, imm5 = (value >>> 16) & 0x1f;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let arrangement;
    if (imm5 & 1) arrangement = Q ? '16b' : '8b';
    else if (imm5 & 2) arrangement = Q ? '8h' : '4h';
    else if (imm5 & 4) arrangement = Q ? '4s' : '2s';
    else if (imm5 & 8) { if (!Q) return null; arrangement = '2d'; }
    else return null;
    let regPrefix = (imm5 & 8) ? 'x' : 'w';
    return `dup v${rd}.${arrangement}, ${regPrefix}${rn}`;
}

function decodeSimdScalarCvtf(value) {
    if (matches(value, 0x9fa1fc00, 0x0e21d800)) {
        let Q = (value >>> 30) & 1, U = (value >>> 29) & 1, size = (value >>> 22) & 3;
        if (size > 1) return null;
        let arr = size === 0 ? (Q ? '4s' : '2s') : (Q ? '2d' : null);
        if (!arr) return null;
        let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
        return `${U ? 'ucvtf' : 'scvtf'} v${rd}.${arr}, v${rn}.${arr}`;
    }
    if (!matches(value, 0xdf3ffc00, 0x5e21d800)) return null;
    let U = (value >>> 29) & 1, size = (value >>> 22) & 3;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let p = size === 0 ? 's' : size === 1 ? 'd' : null;
    if (!p) return null;
    return `${U ? 'ucvtf' : 'scvtf'} ${p}${rd}, ${p}${rn}`;
}

function decodeSimdModifiedImm(value) {

    if (!matches(value, 0x9ff80c00, 0x0f000400)) return null;
    let Q = (value >>> 30) & 1, op = (value >>> 29) & 1;
    let abc = (value >>> 16) & 7, cmode = (value >>> 12) & 0xf;
    let defgh = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let imm8 = (abc << 5) | defgh;

    if (cmode === 0b1110) {
        if (op) {
            let val = 0n;
            for (let i = 0; i < 8; i++) if (imm8 & (1 << i)) val |= 0xffn << BigInt(8 * i);

            let immText = val ? '#0x' + val.toString(16) : '#0000000000000000';
            return Q ? `movi v${rd}.2d, ${immText}` : `movi d${rd}, ${immText}`;
        }
        let arrangement = Q ? '16b' : '8b';
        return `movi v${rd}.${arrangement}, #${imm8}`;
    }
    if (cmode === 0b0000 || cmode === 0b0010 || cmode === 0b0100 || cmode === 0b0110) {

        let shiftAmt = ((cmode >> 1) & 3) * 8;
        let arrangement = Q ? '4s' : '2s';
        let name = op ? 'mvni' : 'movi';
        let val = op ? imm8 : imm8;
        let shStr = shiftAmt ? `, lsl #${shiftAmt}` : '';
        return `${name} v${rd}.${arrangement}, #${val}${shStr}`;
    }
    if (cmode === 0b1000 || cmode === 0b1010) {
        let shiftAmt = ((cmode >> 1) & 1) * 8;
        let arrangement = Q ? '8h' : '4h';
        let name = op ? 'mvni' : 'movi';
        let shStr = shiftAmt ? `, lsl #${shiftAmt}` : '';
        return `${name} v${rd}.${arrangement}, #${imm8}${shStr}`;
    }
    if (cmode === 0b1100 || cmode === 0b1101) {
        let shiftAmt = cmode === 0b1100 ? 8 : 16;
        let arrangement = Q ? '4s' : '2s';
        let name = op ? 'mvni' : 'movi';
        return `${name} v${rd}.${arrangement}, #${imm8}, msl #${shiftAmt}`;
    }
    if (cmode === 0b1111 && !op) {

        let arrangement = Q ? '4s' : '2s';
        let n = fpImm8ToFloat(imm8, false);
        return `fmov v${rd}.${arrangement}, #${formatFpImm(n)}`;
    }
    if (cmode === 0b1111 && op && Q) {
        let n = fpImm8ToFloat(imm8, true);
        return `fmov v${rd}.2d, #${formatFpImm(n)}`;
    }
    if ((cmode & 1) === 1 && cmode !== 0b1111) {

        let is16bit = (cmode & 0b1000) === 0b1000;
        let shiftAmt = is16bit ? ((cmode >> 1) & 1) * 8 : ((cmode >> 1) & 3) * 8;
        let arrangement = is16bit ? (Q ? '8h' : '4h') : (Q ? '4s' : '2s');
        let name = op ? 'bic' : 'orr';
        let shStr = shiftAmt ? `, lsl #${shiftAmt}` : '';
        return `${name} v${rd}.${arrangement}, #${imm8}${shStr}`;
    }
    return null;
}

const simdArrangements = ['8b', '4h', '2s', 'd-invalid'];
function decodeAdvSimd3Same(value) {
    if (!matches(value, 0x9f200400, 0x0e200400)) return null;
    let Q = (value >>> 30) & 1, U = (value >>> 29) & 1;
    let size = (value >>> 22) & 3, rm = (value >>> 16) & 0x1f, opcode = (value >>> 11) & 0x1f;
    let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;

    if (opcode === 0b00011) {
        const names = U ? ['eor', 'bsl', 'bit', 'bif'] : ['and', 'bic', 'orr', 'orn'];
        let name = names[size];
        let arrangement = Q ? '16b' : '8b';
        if (name === 'orr' && rn === rm) return `mov v${rd}.${arrangement}, v${rn}.${arrangement}`;
        return `${name} v${rd}.${arrangement}, v${rn}.${arrangement}, v${rm}.${arrangement}`;
    }

    const intArrangements = { 0: Q ? '16b' : '8b', 1: Q ? '8h' : '4h', 2: Q ? '4s' : '2s', 3: Q ? '2d' : null };

    const intOps = {
        0b00001: ['sqadd',  'uqadd'],
        0b00101: ['sqsub',  'uqsub'],
        0b00110: ['cmgt',   'cmhi'],
        0b00000: ['shadd',  'uhadd'],
        0b00010: ['srhadd', 'urhadd'],
        0b00100: ['shsub',  'uhsub'],
        0b00111: ['cmge',   'cmhs'],
        0b01000: ['sshl',   'ushl'],
        0b01001: ['sqshl',  'uqshl'],
        0b01100: ['smax',   'umax'],
        0b01101: ['smin',   'umin'],
        0b01110: ['sabd',   'uabd'],
        0b01111: ['saba',   'uaba'],
        0b10000: ['add',    'sub'],
        0b10001: ['cmtst',  'cmeq'],
        0b10010: ['mla',    'mls'],
        0b10011: ['mul',    null],
        0b10100: ['smaxp',  'umaxp'],
        0b10101: ['sminp',  'uminp'],
        0b10111: ['addp',   null],
        0b10110: ['sqdmulh', 'sqrdmulh'],
    };
    if (opcode in intOps) {
        let name = intOps[opcode][U];
        if (!name) return null;
        if (opcode === 0b10011 && size === 3) return null;
        if (opcode === 0b10110 && (size === 0 || size === 3)) return null;
        let arrangement = intArrangements[size];
        if (!arrangement) return null;
        return `${name} v${rd}.${arrangement}, v${rn}.${arrangement}, v${rm}.${arrangement}`;
    }

    let a = (size >>> 1) & 1, sz = size & 1;
    let fpArrangement = sz ? (Q ? '2d' : null) : (Q ? '4s' : '2s');
    const fpOps = {
        0b11010: { '0-0': 'fadd', '0-1': 'fsub', '1-0': 'faddp', '1-1': 'fabd' },
        0b11011: { '1-0': 'fmul' },
        0b11111: { '1-0': 'fdiv', '1-1': 'fdiv' },
        0b11110: { '0-0': 'fmax', '0-1': 'fmin' },
        0b11000: { '0-0': 'fmaxnm', '0-1': 'fminnm' },
        0b11001: { '0-0': 'fmla', '0-1': 'fmls' },
        0b11100: { '0-0': 'fcmeq', '1-0': 'fcmge', '1-1': 'fcmgt' },
    };
    if (opcode in fpOps) {
        if (!fpArrangement) return null;
        let name = fpOps[opcode][`${U}-${a}`];
        if (!name) return null;
        return `${name} v${rd}.${fpArrangement}, v${rn}.${fpArrangement}, v${rm}.${fpArrangement}`;
    }
    return null;
}

const simdLdStArrangements = {

    0: { 0: '8b', 1: '16b' },
    1: { 0: '4h', 1: '8h' },
    2: { 0: '2s', 1: '4s' },
    3: { 0: '1d', 1: '2d' },
};

function decodeAdvSimdLdStMultiple(value) {

    let isPost = (value >>> 23) & 1;

    let bits28_24 = (value >>> 24) & 0x1f;
    if (bits28_24 !== 0x0c) return null;
    if ((value >>> 31) & 1) return null;
    if ((value >>> 29) & 1) return null;
    if (!isPost && (((value >>> 16) & 0x3f) !== 0)) return null;

    let Q = (value >>> 30) & 1;
    let L = (value >>> 22) & 1;
    let Rm = isPost ? (value >>> 16) & 0x1f : -1;
    let opc = (value >>> 12) & 0xf;
    let size = (value >>> 10) & 0x3;
    let Rn = (value >>> 5) & 0x1f;
    let Rt = value & 0x1f;

    const opcTable = {
        0x0: [4, true],
        0x2: [4, false],
        0x4: [3, true],
        0x6: [3, false],
        0x7: [1, true],
        0x8: [2, true],
        0xa: [2, false],
        0x8: [2, true],
        0xa: [2, false],
        0x6: [3, false],
        0x2: [4, false],
    };
    const opcInfo = {
        0x0: [4, 'st4', 'ld4'],
        0x4: [3, 'st3', 'ld3'],
        0x7: [1, 'st1', 'ld1'],
        0x8: [2, 'st2', 'ld2'],

        0xa: [2, 'st1', 'ld1'],
        0x6: [3, 'st1', 'ld1'],
        0x2: [4, 'st1', 'ld1'],
    };
    if (!(opc in opcInfo)) return null;
    let [count, stMnem, ldMnem] = opcInfo[opc];
    let mnemonic = L ? ldMnem : stMnem;
    let arr = (simdLdStArrangements[size] || {})[Q];
    if (!arr) return null;

    let regs = [];
    for (let i = 0; i < count; i++) regs.push(`v${(Rt + i) & 31}.${arr}`);
    let regList = `{${regs.join(', ')}}`;
    let rnReg = Rn === 31 ? 'sp' : `x${Rn}`;

    if (!isPost) return `${mnemonic} ${regList}, [${rnReg}]`;

    if (Rm === 31) {

        let bytes = count * (Q ? 16 : 8);
        return `${mnemonic} ${regList}, [${rnReg}], #${bytes}`;
    }
    return `${mnemonic} ${regList}, [${rnReg}], x${Rm}`;
}

function decodeAdvSimdLdStSingle(value) {
    if ((value & 0xbf000000) !== 0x0d000000) return null;

    let Q      = (value >>> 30) & 1;
    let isPost = (value >>> 23) & 1;
    let L      = (value >>> 22) & 1;
    let R      = (value >>> 21) & 1;
    let Rm     = (value >>> 16) & 0x1f;
    let opcode = (value >>> 13) & 0x7;
    let S      = (value >>> 12) & 1;
    let size   = (value >>> 10) & 0x3;
    let Rn     = (value >>> 5)  & 0x1f;
    let Rt     = value          & 0x1f;

    if (!isPost && Rm !== 0) return null;

    let rnReg = Rn === 31 ? 'sp' : `x${Rn}`;

    function postSuffix(elBytes, count) {
        if (!isPost) return '';
        if (Rm === 31) return `, #${elBytes * count}`;
        return `, x${Rm}`;
    }

    if (opcode === 0b110 || opcode === 0b111) {

        if (!L) return null;
        let count = (opcode === 0b110) ? (R ? 2 : 1) : (R ? 4 : 3);
        const sizeNames = ['b', 'h', 's', 'd'];
        const elBytes   = [1, 2, 4, 8];
        const arrNames  = {
            b: Q ? '16b' : '8b',
            h: Q ? '8h'  : '4h',
            s: Q ? '4s'  : '2s',
            d: Q ? '2d'  : '1d',
        };
        let el  = sizeNames[size];
        let arr = arrNames[el];
        let regs = [];
        for (let i = 0; i < count; i++) regs.push(`v${(Rt + i) & 31}.${arr}`);
        let regList = `{${regs.join(', ')}}`;
        let mnem = ['ld1r','ld2r','ld3r','ld4r'][count - 1];
        let suf = postSuffix(elBytes[size], count);
        return `${mnem} ${regList}, [${rnReg}]${suf}`;
    }

    let count;
    let esize;
    let index;

    if (opcode === 0b000) {

        esize = 'b';
        count = R ? 2 : 1;
        index = (Q << 3) | (S << 2) | size;
    } else if (opcode === 0b001) {

        esize = 'b';
        count = R ? 4 : 3;
        index = (Q << 3) | (S << 2) | size;
    } else if (opcode === 0b010) {

        if (size & 1) return null;
        esize = 'h';
        count = R ? 2 : 1;
        index = (Q << 2) | (S << 1) | (size >>> 1);
    } else if (opcode === 0b011) {

        if (size & 1) return null;
        esize = 'h';
        count = R ? 4 : 3;
        index = (Q << 2) | (S << 1) | (size >>> 1);
    } else if (opcode === 0b100) {
        if (size === 0b00 || size === 0b10) {

            esize = 's';
            count = R ? 2 : 1;
            index = (Q << 1) | S;
        } else if (size === 0b01 || size === 0b11) {

            esize = 'd';
            count = R ? 2 : 1;
            if (S !== 0) return null;
            index = Q;
        } else {
            return null;
        }
    } else if (opcode === 0b101) {
        if (size === 0b00 || size === 0b10) {
            esize = 's';
            count = R ? 4 : 3;
            index = (Q << 1) | S;
        } else if (size === 0b01 || size === 0b11) {
            esize = 'd';
            count = R ? 4 : 3;
            if (S !== 0) return null;
            index = Q;
        } else {
            return null;
        }
    } else {
        return null;
    }

    const elBytes = { b: 1, h: 2, s: 4, d: 8 };
    let mnem = (L ? 'ld' : 'st') + count;
    let regs = [];
    for (let i = 0; i < count; i++) regs.push(`v${(Rt + i) & 31}.${esize}`);
    let regList = `{${regs.join(', ')}}[${index}]`;
    let suf = postSuffix(elBytes[esize], count);
    return `${mnem} ${regList}, [${rnReg}]${suf}`;
}

function decodeAdvSimd2RegMisc(value) {
    if (!matches(value, 0x9f3e0c00, 0x0e200800)) return null;
    let Q = (value >>> 30) & 1, U = (value >>> 29) & 1, size = (value >>> 22) & 3;
    let opcode = (value >>> 12) & 0x1f, rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    const intArr = { 0: Q ? '16b' : '8b', 1: Q ? '8h' : '4h', 2: Q ? '4s' : '2s', 3: Q ? '2d' : null };
    const fpArr = (size & 1) ? (Q ? '2d' : null) : (Q ? '4s' : '2s');
    let isFp = (size >>> 1) & 1;

    if (opcode === 0b00000) {
        if (!Q && size === 3) return null;
        let arr = intArr[size];
        if (!arr) return null;
        return `${U ? 'rev32' : 'rev64'} v${rd}.${arr}, v${rn}.${arr}`;
    }
    if (opcode === 0b00001 && !U) {
        let arr = intArr[size];
        if (!arr) return null;
        return `rev16 v${rd}.${arr}, v${rn}.${arr}`;
    }
    if (opcode === 0b00100) {
        if (size !== 0 && size !== 1 && size !== 2) return null;
        let arr = intArr[size];
        return `${U ? 'clz' : 'cls'} v${rd}.${arr}, v${rn}.${arr}`;
    }
    if (opcode === 0b00101) {
        if (size !== 0) return null;
        let arr = intArr[0];
        return `${U ? 'not' : 'cnt'} v${rd}.${arr}, v${rn}.${arr}`;
    }
    if (opcode === 0b01011) {
        let arr = intArr[size];
        if (!arr) return null;
        return `${U ? 'neg' : 'abs'} v${rd}.${arr}, v${rn}.${arr}`;
    }
    if (opcode === 0b01000 || opcode === 0b01001 || opcode === 0b01010) {
        let arr = intArr[size];
        if (!arr) return null;
        const names = { '8-0': 'cmgt', '8-1': 'cmge', '9-0': 'cmeq', '9-1': 'cmle', '10-0': 'cmlt' };
        let name = names[`${opcode}-${U}`];
        if (!name) return null;
        return `${name} v${rd}.${arr}, v${rn}.${arr}, #0`;
    }
    if (opcode === 0b01111 || opcode === 0b11111) {
        if (!fpArr) return null;
        if (opcode === 0b11111) { if (!U) return null; return `fsqrt v${rd}.${fpArr}, v${rn}.${fpArr}`; }
        return `${U ? 'fneg' : 'fabs'} v${rd}.${fpArr}, v${rn}.${fpArr}`;
    }
    if (opcode === 0b01100 || opcode === 0b01101 || opcode === 0b01110) {
        if (!fpArr) return null;
        const names = { '12-0': 'fcmgt', '12-1': 'fcmge', '13-0': 'fcmeq', '13-1': 'fcmle', '14-0': 'fcmlt' };
        let name = names[`${opcode}-${U}`];
        if (!name) return null;
        return `${name} v${rd}.${fpArr}, v${rn}.${fpArr}, #0.0`;
    }

    if (opcode === 0x12) {
        if (size > 2) return null;
        const srcArr = ['8h', '4s', '2d'][size];
        const dstArr = [Q ? '16b' : '8b', Q ? '8h' : '4h', Q ? '4s' : '2s'][size];
        const mnem = (U ? 'sqxtun' : 'xtn') + (Q ? '2' : '');
        return `${mnem} v${rd}.${dstArr}, v${rn}.${srcArr}`;
    }

    if (opcode === 0x14) {
        if (size > 2) return null;
        const srcArr = ['8h', '4s', '2d'][size];
        const dstArr = [Q ? '16b' : '8b', Q ? '8h' : '4h', Q ? '4s' : '2s'][size];
        const mnem = (U ? 'uqxtn' : 'sqxtn') + (Q ? '2' : '');
        return `${mnem} v${rd}.${dstArr}, v${rn}.${srcArr}`;
    }

    if (opcode === 0x16) {
        if (!U) {
            if (size === 0) return `${Q ? 'fcvtn2' : 'fcvtn'} v${rd}.${Q ? '8h' : '4h'}, v${rn}.4s`;
            if (size === 1) return `${Q ? 'fcvtn2' : 'fcvtn'} v${rd}.${Q ? '4s' : '2s'}, v${rn}.2d`;
            return null;
        }

        if (size === 1) return `${Q ? 'fcvtxn2' : 'fcvtxn'} v${rd}.${Q ? '4s' : '2s'}, v${rn}.2d`;
        return null;
    }

    if (opcode === 0x17 && !U) {
        if (size === 0) return `${Q ? 'fcvtl2' : 'fcvtl'} v${rd}.4s, v${rn}.${Q ? '8h' : '4h'}`;
        if (size === 1) return `${Q ? 'fcvtl2' : 'fcvtl'} v${rd}.2d, v${rn}.${Q ? '4s' : '2s'}`;
        return null;
    }

    if (opcode === 0b11000 || opcode === 0b11001) {
        if (!fpArr) return null;
        const names = {
            '24-0-0': 'frintn', '24-0-1': 'frintp', '24-1-0': 'frinta',
            '25-0-0': 'frintm', '25-0-1': 'frintz', '25-1-0': 'frintx', '25-1-1': 'frinti',
        };
        let name = names[`${opcode}-${U}-${isFp}`];
        if (!name) return null;
        return `${name} v${rd}.${fpArr}, v${rn}.${fpArr}`;
    }
    return null;
}

function decodeAdvSimdDot(value) {
    if ((value >>> 31) & 1) return null;
    if (((value >>> 24) & 0x1f) !== 0b01110) return null;
    if (((value >>> 22) & 3) !== 2) return null;
    if ((value >>> 21) & 1) return null;
    if (((value >>> 10) & 0x3f) !== 0b100101) return null;

    let Q = (value >>> 30) & 1, U = (value >>> 29) & 1;
    let rm = (value >>> 16) & 0x1f, rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    let name = U ? 'udot' : 'sdot';
    let dstArr = Q ? '4s' : '2s';
    let srcArr = Q ? '16b' : '8b';
    return `${name} v${rd}.${dstArr}, v${rn}.${srcArr}, v${rm}.${srcArr}`;
}

function encAdvSimdDot(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]), rm = parseSimdReg(ops[2]);
    let Q = /^(16b|4s)$/.test(rd.arrangement) || rd.arrangement === '4s' ? 1 : 0;
    Q = QfromArr(rd.arrangement);
    if (Q === null) throw new Error(`Bad arrangement for ${mnemonic}: ${rd.arrangement}`);
    let U = mnemonic === 'udot' ? 1 : 0;
    return ((Q << 30) | (U << 29) | (0b01110 << 24) | (2 << 22) | (0b100101 << 10) | (rm.num << 16) | (rn.num << 5) | rd.num) >>> 0;
}

function decodeAdvSimd3Different(value) {
    if (!matches(value, 0x9f200c00, 0x0e200000)) return null;
    let Q = (value >>> 30) & 1, U = (value >>> 29) & 1, size = (value >>> 22) & 3;
    let rm = (value >>> 16) & 0x1f, opcode = (value >>> 12) & 0xf, rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
    if (size === 3) {
        if (opcode === 14 && U === 0) {
            const srcArr = Q ? '2d' : '1d';
            return `pmull${Q ? '2' : ''} v${rd}.1q, v${rn}.${srcArr}, v${rm}.${srcArr}`;
        }
        return null;
    }

    const narrowArr = [Q ? '16b' : '8b', Q ? '8h' : '4h', Q ? '4s' : '2s'][size];
    const wideArr = ['8h', '4s', '2d'][size];
    const suffix2 = Q ? '2' : '';

    const longOps = { 0: 'saddl', 2: 'ssubl', 5: 'sabal', 7: 'sabdl', 8: 'smlal', 10: 'smlsl', 12: 'smull' };
    const longOpsU = { 0: 'uaddl', 2: 'usubl', 5: 'uabal', 7: 'uabdl', 8: 'umlal', 10: 'umlsl', 12: 'umull' };
    const wideOps = { 1: 'saddw', 3: 'ssubw' };
    const wideOpsU = { 1: 'uaddw', 3: 'usubw' };
    const narrowOps = { 4: 'addhn', 6: 'subhn' };
    const narrowOpsU = { 4: 'raddhn', 6: 'rsubhn' };

    if (opcode in longOps) {
        let name = (U ? longOpsU : longOps)[opcode] + suffix2;
        return `${name} v${rd}.${wideArr}, v${rn}.${narrowArr}, v${rm}.${narrowArr}`;
    }
    if (opcode in wideOps) {
        let name = (U ? wideOpsU : wideOps)[opcode] + suffix2;
        return `${name} v${rd}.${wideArr}, v${rn}.${wideArr}, v${rm}.${narrowArr}`;
    }
    if (opcode in narrowOps) {
        let name = (U ? narrowOpsU : narrowOps)[opcode] + suffix2;
        return `${name} v${rd}.${narrowArr}, v${rn}.${wideArr}, v${rm}.${wideArr}`;
    }
    if (opcode === 14 && U === 0 && size === 0) {
        return `pmull${suffix2} v${rd}.${wideArr}, v${rn}.${narrowArr}, v${rm}.${narrowArr}`;
    }
    return null;
}

function decodeAdvSimdScalarByElement(value) {
    if ((value >>> 31) & 1) return null;
    if (((value >>> 30) & 1) !== 1) return null;
    if (((value >>> 24) & 0x1f) !== 0b11111) return null;
    if ((value >>> 10) & 1) return null;

    let U = (value >>> 29) & 1, size = (value >>> 22) & 3;
    let L = (value >>> 21) & 1, M = (value >>> 20) & 1, rmLow = (value >>> 16) & 0xf;
    let opcode = (value >>> 12) & 0xf, H = (value >>> 11) & 1;
    let Rn = (value >>> 5) & 0x1f, Rd = value & 0x1f;
    if (U !== 0) return null;
    if (opcode !== 0b1100 && opcode !== 0b1101) return null;
    let name = opcode === 0b1100 ? 'sqdmulh' : 'sqrdmulh';

    let rm, index, p, idxArr;
    if (size === 1) { rm = rmLow; index = (H << 2) | (L << 1) | M; p = 'h'; idxArr = 'h'; }
    else if (size === 2) { rm = (M << 4) | rmLow; index = (H << 1) | L; p = 's'; idxArr = 's'; }
    else return null;

    return `${name} ${p}${Rd}, ${p}${Rn}, v${rm}.${idxArr}[${index}]`;
}

function decodeAdvSimdVectorByElement(value) {
    if (!matches(value, 0x9f000400, 0x0f000000)) return null;
    let Q = (value >>> 30) & 1, U = (value >>> 29) & 1, size = (value >>> 22) & 3;
    let L = (value >>> 21) & 1, M = (value >>> 20) & 1, rmLow = (value >>> 16) & 0xf;
    let opcode = (value >>> 12) & 0xf, H = (value >>> 11) & 1, rn = (value >>> 5) & 0x1f, rd = value & 0x1f;

    let rm, index;
    if (size === 1) { rm = rmLow; index = (H << 2) | (L << 1) | M; }
    else { rm = (M << 4) | rmLow; index = (H << 1) | L; if (size === 3) index = H; }

    const intArr = { 1: Q ? '8h' : '4h', 2: Q ? '4s' : '2s' }[size];
    const longSrcArr = { 1: Q ? '8h' : '4h', 2: Q ? '4s' : '2s' }[size];
    const longSrcIdxArr = { 1: 'h', 2: 's' }[size];
    const longDstArr = { 1: '4s', 2: '2d' }[size];
    const fpArr = size === 3 ? '2d' : (Q ? '4s' : '2s');
    const idxArr = { 1: 'h', 2: 's', 3: 'd' }[size];

    if (opcode === 0b1000 && U === 0) {
        if (!intArr) return null;
        return `mul v${rd}.${intArr}, v${rn}.${intArr}, v${rm}.${idxArr}[${index}]`;
    }
    if (opcode === 0b0000 && U === 1) {
        if (!intArr) return null;
        return `mla v${rd}.${intArr}, v${rn}.${intArr}, v${rm}.${idxArr}[${index}]`;
    }
    if (opcode === 0b0100 && U === 1) {
        if (!intArr) return null;
        return `mls v${rd}.${intArr}, v${rn}.${intArr}, v${rm}.${idxArr}[${index}]`;
    }
    if (opcode === 0b1001 && U === 0) {
        if (size !== 2 && size !== 3) return null;
        return `fmul v${rd}.${fpArr}, v${rn}.${fpArr}, v${rm}.${idxArr}[${index}]`;
    }
    if (opcode === 0b0001 && U === 0) {
        if (size !== 2 && size !== 3) return null;
        return `fmla v${rd}.${fpArr}, v${rn}.${fpArr}, v${rm}.${idxArr}[${index}]`;
    }
    if (opcode === 0b0101 && U === 0) {
        if (size !== 2 && size !== 3) return null;
        return `fmls v${rd}.${fpArr}, v${rn}.${fpArr}, v${rm}.${idxArr}[${index}]`;
    }
    if (opcode === 0b1010) {
        if (size !== 1 && size !== 2) return null;
        let name = (U ? 'umull' : 'smull') + (Q ? '2' : '');
        return `${name} v${rd}.${longDstArr}, v${rn}.${longSrcArr}, v${rm}.${longSrcIdxArr}[${index}]`;
    }
    if (opcode === 0b0010) {
        if (size !== 1 && size !== 2) return null;
        let name = (U ? 'umlal' : 'smlal') + (Q ? '2' : '');
        return `${name} v${rd}.${longDstArr}, v${rn}.${longSrcArr}, v${rm}.${longSrcIdxArr}[${index}]`;
    }
    if (opcode === 0b0110) {
        if (size !== 1 && size !== 2) return null;
        let name = (U ? 'umlsl' : 'smlsl') + (Q ? '2' : '');
        return `${name} v${rd}.${longDstArr}, v${rn}.${longSrcArr}, v${rm}.${longSrcIdxArr}[${index}]`;
    }
    if (opcode === 0b1011 && U === 0) {
        if (size !== 1 && size !== 2) return null;
        let name = 'sqdmull' + (Q ? '2' : '');
        return `${name} v${rd}.${longDstArr}, v${rn}.${longSrcArr}, v${rm}.${longSrcIdxArr}[${index}]`;
    }
    if (opcode === 0b1100 && U === 0) {
        if (!intArr) return null;
        return `sqdmulh v${rd}.${intArr}, v${rn}.${intArr}, v${rm}.${idxArr}[${index}]`;
    }
    if (opcode === 0b1101 && U === 0) {
        if (!intArr) return null;
        return `sqrdmulh v${rd}.${intArr}, v${rn}.${intArr}, v${rm}.${idxArr}[${index}]`;
    }
    return null;
}

function decodeAdvSimdScalarShiftByImm(value) {
    if ((value >>> 31) & 1) return null;
    if (((value >>> 30) & 1) !== 1) return null;
    if (((value >>> 23) & 0x3f) !== 0b111110) return null;
    if (!((value >>> 10) & 1)) return null;

    let U = (value >>> 29) & 1;
    let immh = (value >>> 19) & 0xf, immb = (value >>> 16) & 7;
    let opcode = (value >>> 11) & 0x1f;
    let Rn = (value >>> 5) & 0x1f, Rd = value & 0x1f;
    if (immh === 0 || !(immh & 8)) return null;
    let immhb = (immh << 3) | immb;

    const rightShift = {
        0x00: ['sshr', 'ushr'], 0x02: ['ssra', 'usra'], 0x04: ['srshr', 'urshr'], 0x06: ['srsra', 'ursra'],
        0x08: [null, 'sri'],
    };
    const leftShift = {
        0x0a: ['shl', 'sli'], 0x0c: [null, 'sqshlu'], 0x0e: ['sqshl', 'uqshl'],
    };
    if (opcode in rightShift) {
        let shiftAmt = 128 - immhb;
        let name = rightShift[opcode][U];
        if (!name) return null;
        return `${name} d${Rd}, d${Rn}, #${shiftAmt}`;
    }
    if (opcode in leftShift) {
        let shiftAmt = immhb - 64;
        let name = leftShift[opcode][U];
        if (!name) return null;
        return `${name} d${Rd}, d${Rn}, #${shiftAmt}`;
    }
    return null;
}

function decodeAdvSimdShiftByImm(value) {
    if ((value >>> 31) & 1) return null;
    if (((value >>> 23) & 0x3f) !== 0x1e) return null;
    if (!((value >>> 10) & 1)) return null;

    let Q = (value >>> 30) & 1;
    let U = (value >>> 29) & 1;
    let immh = (value >>> 19) & 0xf;
    let immb = (value >>> 16) & 0x7;
    let opcode = (value >>> 11) & 0x1f;
    let Rn = (value >>> 5) & 0x1f;
    let Rd = value & 0x1f;

    if (immh === 0) return null;

    let esize, sizeIdx;
    if (immh & 8) { esize = 64; sizeIdx = 3; }
    else if (immh & 4) { esize = 32; sizeIdx = 2; }
    else if (immh & 2) { esize = 16; sizeIdx = 1; }
    else { esize = 8; sizeIdx = 0; }

    if (esize === 64 && !Q) return null;

    const arrMap = {
        0: { 0: '8b', 1: '16b' },
        1: { 0: '4h', 1: '8h' },
        2: { 0: '2s', 1: '4s' },
        3: { 0: '1d' , 1: '2d' },
    };
    let arr = arrMap[sizeIdx][Q];
    if (!arr) return null;

    let immhb = (immh << 3) | immb;

    const rightShift = {
        0x00: ['sshr', 'ushr'],
        0x02: ['ssra', 'usra'],
        0x04: ['srshr', 'urshr'],
        0x06: ['srsra', 'ursra'],
        0x08: [null,    'sri'],
    };
    const leftShift = {
        0x0a: ['shl',   'sli'],
        0x0c: ['sqshl', 'sqshlu'],
        0x0e: ['sqshl', 'uqshl'],
    };

    if (opcode === 0x14) {
        let shiftAmt = immhb - esize;
        const wideArr = { 0: '8h', 1: '4s', 2: '2d' };
        let dstArr = wideArr[sizeIdx];
        if (!dstArr) return null;
        let srcArr = arrMap[sizeIdx][Q];
        if (shiftAmt === 0) {
            return `${U ? 'uxtl' : 'sxtl'}${Q ? '2' : ''} v${Rd}.${dstArr}, v${Rn}.${srcArr}`;
        }
        return `${U ? 'ushll' : 'sshll'}${Q ? '2' : ''} v${Rd}.${dstArr}, v${Rn}.${srcArr}, #${shiftAmt}`;
    }

    if (opcode >= 0x10 && opcode <= 0x13) {

        if (sizeIdx === 3) return null;

        let dst_esize = esize;
        let src_esize = esize * 2;
        let shiftAmt = src_esize - immhb;
        if (shiftAmt <= 0 || shiftAmt > dst_esize) return null;

        const narrowDstQ0 = ['8b', '4h', '2s'][sizeIdx];
        const narrowDstQ1 = ['16b', '8h', '4s'][sizeIdx];
        let dstArr = Q ? narrowDstQ1 : narrowDstQ0;
        let srcArr = arrMap[sizeIdx + 1][1];

        let mnem;
        if      (opcode === 0x10 && !U) mnem = 'shrn';
        else if (opcode === 0x10 &&  U) mnem = 'sqshrun';
        else if (opcode === 0x11 && !U) mnem = 'rshrn';
        else if (opcode === 0x11 &&  U) mnem = 'sqrshrun';
        else if (opcode === 0x12 && !U) mnem = 'sqshrn';
        else if (opcode === 0x12 &&  U) mnem = 'uqshrn';
        else if (opcode === 0x13 && !U) mnem = 'sqrshrn';
        else                            mnem = 'uqrshrn';

        return `${mnem}${Q ? '2' : ''} v${Rd}.${dstArr}, v${Rn}.${srcArr}, #${shiftAmt}`;
    }

    if (opcode in rightShift) {
        let shiftAmt = esize * 2 - immhb;
        let names = rightShift[opcode];
        let name = names[U];
        if (!name) return null;
        return `${name} v${Rd}.${arr}, v${Rn}.${arr}, #${shiftAmt}`;
    }
    if (opcode in leftShift) {
        let shiftAmt = immhb - esize;
        let names = leftShift[opcode];
        let name = names[U];
        if (!name) return null;
        return `${name} v${Rd}.${arr}, v${Rn}.${arr}, #${shiftAmt}`;
    }
    return null;
}

function decodeAdvSimdPermute(value) {
    if ((value >>> 31) & 1) return null;
    if (((value >>> 24) & 0x3f) !== 0x0e) return null;
    if ((value >>> 21) & 1) return null;
    if (((value >>> 10) & 3) !== 2) return null;
    if ((value >>> 15) & 1) return null;

    let Q = (value >>> 30) & 1;
    let size = (value >>> 22) & 3;
    let Rm = (value >>> 16) & 0x1f;
    let opc = (value >>> 12) & 7;
    let Rn = (value >>> 5) & 0x1f;
    let Rd = value & 0x1f;

    const arrMap = {
        0: Q ? '16b' : '8b',
        1: Q ? '8h' : '4h',
        2: Q ? '4s' : '2s',
        3: Q ? '2d' : null,
    };
    let arr = arrMap[size];
    if (!arr) return null;

    const opcNames = { 1: 'uzp1', 2: 'trn1', 3: 'zip1', 5: 'uzp2', 6: 'trn2', 7: 'zip2' };
    let name = opcNames[opc];
    if (!name) return null;

    return `${name} v${Rd}.${arr}, v${Rn}.${arr}, v${Rm}.${arr}`;
}

function decodeAdvSimdTblTbx(value) {
    if ((value >>> 31) & 1) return null;
    if (((value >>> 22) & 0xff) !== 0x38) return null;
    if ((value >>> 15) & 1) return null;
    if (((value >>> 10) & 3) !== 0) return null;

    let Q = (value >>> 30) & 1;
    let Rm = (value >>> 16) & 0x1f;
    let len = (value >>> 13) & 3;
    let op = (value >>> 12) & 1;
    let Rn = (value >>> 5) & 0x1f;
    let Rd = value & 0x1f;

    len = (value >>> 13) & 3;
    op = (value >>> 12) & 1;

    let count = len + 1;
    let arr = Q ? '16b' : '8b';
    let regs = [];
    for (let i = 0; i < count; i++) regs.push(`v${(Rn + i) & 31}.16b`);
    let regList = `{${regs.join(', ')}}`;
    return `${op ? 'tbx' : 'tbl'} v${Rd}.${arr}, ${regList}, v${Rm}.${arr}`;
}

function decodeAdvSimdExt(value) {
    if ((value >>> 31) & 1) return null;
    if (((value >>> 24) & 0x3f) !== 0x2e) return null;
    if (((value >>> 22) & 3) !== 0) return null;
    if ((value >>> 21) & 1) return null;
    if ((value >>> 10) & 1) return null;

    let Q = (value >>> 30) & 1;
    let Rm = (value >>> 16) & 0x1f;
    let index = (value >>> 11) & 0xf;
    index = (value >>> 11) & 0xf;
    let Rn = (value >>> 5) & 0x1f;
    let Rd = value & 0x1f;

    index = (value >>> 11) & 0xf;
    let arr = Q ? '16b' : '8b';
    if (!Q && index >= 8) return null;
    return `ext v${Rd}.${arr}, v${Rn}.${arr}, v${Rm}.${arr}, #${index}`;
}

function decodeAdvSimdAcrossLanes(value) {
    if ((value >>> 31) & 1) return null;
    if (((value >>> 24) & 0x1f) !== 0x0e) return null;
    if (((value >>> 17) & 0x1f) !== 0x18) return null;

    if (((value >>> 10) & 3) !== 2) return null;

    let Q = (value >>> 30) & 1;
    let U = (value >>> 29) & 1;
    let size = (value >>> 22) & 3;
    let opc = (value >>> 12) & 0x1f;
    let Rn = (value >>> 5) & 0x1f;
    let Rd = value & 0x1f;

    const intOps = {
        0x1b: { 0: 'addv', 1: 'addv' },
        0x0a: { 0: 'smaxv', 1: 'umaxv' },
        0x1a: { 0: 'sminv', 1: 'uminv' },
    };
    if (opc in intOps) {
        let name = (intOps[opc])[U];
        if (!name) return null;
        const arrMap = {
            0: { 0: '8b', 1: '16b' },
            1: { 0: '4h', 1: '8h' },
            2: { 0: '2s' , 1: '4s' },
        };
        let srcArr = (arrMap[size] || {})[Q];
        if (!srcArr) return null;
        const dstPfx = { 0: 'b', 1: 'h', 2: 's' };
        let dstP = dstPfx[size];
        if (!dstP) return null;
        return `${name} ${dstP}${Rd}, v${Rn}.${srcArr}`;
    }
    if (opc === 0x03) {

        const name = U ? 'uaddlv' : 'saddlv';
        const arrMap = {
            0: { 0: '8b', 1: '16b' },
            1: { 0: '4h', 1: '8h' },
            2: { 0: '2s' , 1: '4s' },
        };
        let srcArr = (arrMap[size] || {})[Q];
        if (!srcArr) return null;
        const dstPfxLong = { 0: 'h', 1: 's', 2: 'd' };
        let dstP = dstPfxLong[size];
        if (!dstP) return null;
        return `${name} ${dstP}${Rd}, v${Rn}.${srcArr}`;
    }

    const fpOps = {
        0x0c: { 0: 'fmaxnmv', 1: 'fminnmv' },
        0x0f: { 0: 'fmaxv', 1: 'fminv' },
    };
    if (opc in fpOps) {
        if ((size & 1) !== 0 || !Q) return null;
        let a = (size >>> 1) & 1;
        let name = (fpOps[opc])[a];
        if (!name) return null;
        return `${name} s${Rd}, v${Rn}.4s`;
    }
    return null;
}

function decodeAdvSimdScalar3Same(value) {
    if (((value >>> 30) & 3) !== 1) return null;
    if (((value >>> 24) & 0x1f) !== 0x1e) return null;

    if (!((value >>> 21) & 1)) return null;
    if (!((value >>> 10) & 1)) return null;

    let U = (value >>> 29) & 1;
    let size = (value >>> 22) & 3;
    let Rm = (value >>> 16) & 0x1f;
    let opc = (value >>> 11) & 0x1f;
    let Rn = (value >>> 5) & 0x1f;
    let Rd = value & 0x1f;

    const sizeReg = ['b', 'h', 's', 'd'];

    const satOps = {
        0b00001: ['sqadd', 'uqadd'],
        0b00101: ['sqsub', 'uqsub'],
        0b01001: ['sqshl', 'uqshl'],
    };
    if (opc in satOps) {
        let name = satOps[opc][U];
        if (!name) return null;
        let r = sizeReg[size];
        return `${name} ${r}${Rd}, ${r}${Rn}, ${r}${Rm}`;
    }

    if (opc === 0b10110 && (size === 1 || size === 2)) {
        let name = U ? 'sqrdmulh' : 'sqdmulh';
        let r = sizeReg[size];
        return `${name} ${r}${Rd}, ${r}${Rn}, ${r}${Rm}`;
    }

    if (size !== 3) return null;

    const ops3Same = {
        0b10000: ['add',   'sub'],
        0b10001: ['cmtst', 'cmeq'],
        0b00110: ['cmgt',  'cmhi'],
        0b00111: ['cmge',  'cmhs'],
        0b01000: ['sshl',  'ushl'],
    };
    if (!(opc in ops3Same)) return null;
    let name = ops3Same[opc][U];
    if (!name) return null;
    return `${name} d${Rd}, d${Rn}, d${Rm}`;
}

function decodeAdvSimdScalarPairwise(value) {
    if (((value >>> 30) & 3) !== 1) return null;
    if (((value >>> 24) & 0x1f) !== 0x1e) return null;
    if (((value >>> 17) & 0x1f) !== 0x18) return null;
    if (((value >>> 10) & 3) !== 2) return null;

    let U = (value >>> 29) & 1;
    let size = (value >>> 22) & 3;
    let opc = (value >>> 12) & 0x1f;
    let Rn = (value >>> 5) & 0x1f;
    let Rd = value & 0x1f;

    if (opc === 0b11011 && !U && size === 3) {
        return `addp d${Rd}, v${Rn}.2d`;
    }
    return null;
}

function decodeAdvSimdScalar2RegMisc(value) {
    if (((value >>> 30) & 3) !== 1) return null;
    if (((value >>> 24) & 0x1f) !== 0x1e) return null;
    if (((value >>> 17) & 0x1f) !== 0x10) return null;
    if (((value >>> 10) & 3) !== 2) return null;

    let U = (value >>> 29) & 1;
    let size = (value >>> 22) & 3;
    let opc = (value >>> 12) & 0x1f;
    let Rn = (value >>> 5) & 0x1f;
    let Rd = value & 0x1f;

    if (opc === 0x14 && size <= 2) {
        const dstReg = ['b', 'h', 's'][size];
        const srcReg = ['h', 's', 'd'][size];
        const mnem = U ? 'uqxtn' : 'sqxtn';
        return `${mnem} ${dstReg}${Rd}, ${srcReg}${Rn}`;
    }

    if (opc === 0x12 && U && size <= 2) {
        const dstReg = ['b', 'h', 's'][size];
        const srcReg = ['h', 's', 'd'][size];
        return `sqxtun ${dstReg}${Rd}, ${srcReg}${Rn}`;
    }

    if (opc === 0x16 && U && size === 1) {
        return `fcvtxn s${Rd}, d${Rn}`;
    }

    if (size !== 3) return null;
    const miscOps = {
        0x08: ['cmgt', 'cmge'],
        0x09: ['cmeq', null],
        0x0a: ['cmlt', 'cmle'],
        0x0b: ['abs', 'neg'],
    };
    if (!(opc in miscOps)) return null;
    let name = miscOps[opc][U];
    if (!name) return null;
    if (opc === 0x0b) return `${name} d${Rd}, d${Rn}`;
    return `${name} d${Rd}, d${Rn}, #0`;
}

function decodeSystemRegName(fields) {
    let known = systemEncodingToReg[fields >>> 0];
    if (known) return known;
    return genericSysRegFieldsToName(fields);
}

function decodePac(value) {

    if (!matches(value, 0xFFFF8000, 0xDAC10000)) return null;
    let Rd = value & 0x1f;
    let Rn = (value >>> 5) & 0x1f;
    let opc5 = (value >>> 10) & 0x1f;

    const pac2reg = {
        0: ['pacia', false], 1: ['pacib', false],
        2: ['pacda', false], 3: ['pacdb', false],
        4: ['autia', false], 5: ['autib', false],
        6: ['autda', false], 7: ['autdb', false],
        8: ['paciza', true], 9: ['pacizb', true],
        10: ['pacdza', true], 11: ['pacdzb', true],
        12: ['autiza', true], 13: ['autizb', true],
        14: ['autdza', true], 15: ['autdzb', true],
        16: ['xpaci', true], 17: ['xpacd', true],
    };
    if (!(opc5 in pac2reg)) return null;
    let [name, noRn] = pac2reg[opc5];
    if (noRn) return `${name} x${Rd}`;
    return `${name} x${Rd}, x${Rn}`;
}

function decodeAuthBranch(value) {

    if (!matches(value, 0xfe9f0000, 0xd61f0000)) return null;
    let opc = (value >>> 21) & 0xf, op3 = (value >>> 10) & 0x3f, rn = (value >>> 5) & 0x1f, rm = value & 0x1f;
    let link = (opc & 1) === 1, hasReg = (opc & 8) === 8;
    if ((opc & 0x6) !== 0) return null;
    if (op3 !== 0b000010 && op3 !== 0b000011) return null;
    let key = (op3 & 1) === 0 ? 'a' : 'b';
    let name = `${link ? 'blr' : 'br'}a${key}`;
    if (hasReg) return `${name} x${rn}, ${rm === 31 ? 'sp' : `x${rm}`}`;
    if (rm !== 31) return null;
    return `${name}z x${rn}`;
}

function decodeMte(value) {

    if (matches(value, 0xFFE0FC00, 0x9AC01000)) {
        let Rd = value & 0x1f, Rn = (value >>> 5) & 0x1f, Rm = (value >>> 16) & 0x1f;
        if (Rm === 31) return `irg x${Rd}, x${Rn}`;
        return `irg x${Rd}, x${Rn}, x${Rm}`;
    }

    if (matches(value, 0xFFE0FC00, 0x9AC01400)) {
        let Rd = value & 0x1f, Rn = (value >>> 5) & 0x1f, Rm = (value >>> 16) & 0x1f;
        return `gmi x${Rd}, x${Rn}, x${Rm}`;
    }

    if (matches(value, 0xFFC0C000, 0x91800000)) {
        let Rd = value & 0x1f, Rn = (value >>> 5) & 0x1f;
        let uimm4 = (value >>> 10) & 0xf, uimm6 = (value >>> 16) & 0x3f;
        return `addg x${Rd}, x${Rn}, #${uimm6 * 16}, #${uimm4}`;
    }

    if (matches(value, 0xFFC0C000, 0xD1800000)) {
        let Rd = value & 0x1f, Rn = (value >>> 5) & 0x1f;
        let uimm4 = (value >>> 10) & 0xf, uimm6 = (value >>> 16) & 0x3f;
        return `subg x${Rd}, x${Rn}, #${uimm6 * 16}, #${uimm4}`;
    }

    if (matches(value, 0xFF200000, 0xD9200000)) {
        let opc = (value >>> 22) & 3;
        let op2 = (value >>> 10) & 3;
        let imm9 = signExtend((value >>> 12) & 0x1ff, 9) * 16;
        let Rn = (value >>> 5) & 0x1f;
        let Rt = value & 0x1f;
        const rnStr = Rn === 31 ? 'sp' : `x${Rn}`;
        const rtStr = Rt === 31 ? 'sp' : `x${Rt}`;
        if (op2 === 0) {
            if (opc === 1) return `ldg ${rtStr}, [${rnStr}${imm9 ? `, #${imm9}` : ''}]`;
            if (opc === 0) return `stgm ${rtStr}, [${rnStr}]`;
            if (opc === 3) return `ldgm ${rtStr}, [${rnStr}]`;
            return null;
        }
        const names = ['stg', 'stzg', 'st2g', 'stz2g'];
        let name = names[opc];
        if (op2 === 1) return `${name} ${rtStr}, [${rnStr}], #${imm9}`;
        if (op2 === 3) return `${name} ${rtStr}, [${rnStr}, #${imm9}]!`;
        if (op2 === 2) {
            let offStr = imm9 ? `, #${imm9}` : '';
            return `${name} ${rtStr}, [${rnStr}${offStr}]`;
        }
        return null;
    }
    return null;
}

function decodeMrsMsrRegister(value) {

    if (!matches(value, 0xffd00000, 0xd5100000)) return null;
    let L = (value >>> 21) & 1;
    let rt = value & 0x1f;

    let lookupKey = (value | 0x00200000) & 0xffffffe0;
    let sysName = decodeSystemRegName(lookupKey);
    if (L) return `mrs x${rt}, ${sysName}`;
    return `msr ${sysName}, x${rt}`;
}

function decodeArm64(value, littleEndian) {
    if (littleEndian) value = reverseBytes(value);
    value >>>= 0;

    for (let [name, enc] of Object.entries(fixedArm64)) {
        if (value === (enc >>> 0)) return name;
    }
    if (matches(value, 0xfffffc1f, 0xd65f0000)) {
        let rn = (value >>> 5) & 0x1f;
        return rn === 31 ? 'ret' : `ret x${rn}`;
    }
    if (matches(value, 0xfffffc1f, 0xd61f0000)) return `br x${(value >>> 5) & 0x1f}`;
    if (matches(value, 0xfffffc1f, 0xd63f0000)) return `blr x${(value >>> 5) & 0x1f}`;
    if (matches(value, 0xffe0001f, 0xd4000001)) return `svc ${immStr((value >>> 5) & 0xffff)}`;
    if (matches(value, 0xffffffe0, 0xd53bd040) || matches(value, 0xffffffe0, 0xd53bd060) ||
        matches(value, 0xffffffe0, 0xd53be040) || matches(value, 0xffffffe0, 0xd53be000) ||
        matches(value, 0xffffffe0, 0xd53b4400) || matches(value, 0xffffffe0, 0xd53b4420)) {
        let sys = systemEncodingToReg[(value & 0xffffffe0) >>> 0];
        return `mrs x${value & 0x1f}, ${sys}`;
    }
    { let d = decodeMrsMsrRegister(value); if (d) return d; }
    { let d = decodePac(value); if (d) return d; }
    { let d = decodeAuthBranch(value); if (d) return d; }
    { let d = decodeMte(value); if (d) return d; }

    if (matches(value, 0x1f000000, 0x10000000)) {
        let op = (value >>> 31) & 1;
        let imm = (((value >>> 5) & 0x7ffff) << 2) | ((value >>> 29) & 3);
        imm = signExtend(imm, 21);
        let rd = value & 0x1f;
        return `${op ? 'adrp' : 'adr'} ${reg('x', rd)}, ${immStr(op ? imm * 4096 : imm)}`;
    }

    if (matches(value, 0x1f000000, 0x11000000)) {
        let sf = (value >>> 31) & 1, op = (value >>> 30) & 1, s = (value >>> 29) & 1;
        let imm = ((value >>> 10) & 0xfff) << (((value >>> 22) & 1) ? 12 : 0);
        let rn = (value >>> 5) & 0x1f, rd = value & 0x1f;
        let p = sf ? 'x' : 'w';
        let rnReg = rn === 31 ? (sf ? 'sp' : 'wsp') : `${p}${rn}`;
        if (s && rd === 31) {
            return `${op ? 'cmp' : 'cmn'} ${rnReg}, #${imm}`;
        }
        if (!op && !s && imm === 0 && (rd === 31 || rn === 31)) {
            let rdReg2 = rd === 31 ? (sf ? 'sp' : 'wsp') : `${p}${rd}`;
            return `mov ${rdReg2}, ${rnReg}`;
        }
        let rdReg = rd === 31 ? (sf ? 'sp' : 'wsp') : `${p}${rd}`;
        return `${op ? 'sub' : 'add'}${s ? 's' : ''} ${rdReg}, ${rnReg}, #${imm}`;
    }

    if (matches(value, 0x7f800000, 0x52800000) || matches(value, 0x7f800000, 0x12800000)) {
        let sf = (value >>> 31) & 1, hw = (value >>> 21) & 3, imm16 = (value >>> 5) & 0xffff, rd = value & 0x1f;
        let isMovn = matches(value, 0x7f800000, 0x12800000);
        let p = sf ? 'x' : 'w';
        if (isMovn) {

            if (!(imm16 === 0 && hw !== 0)) {
                let width = sf ? 64n : 32n;
                let mask = (1n << width) - 1n;
                let val = (~(BigInt(imm16) << BigInt(hw * 16))) & mask;
                let signedVal = val >= (1n << (width - 1n)) ? val - (1n << width) : val;
                return `mov ${p}${rd}, #${signedVal.toString(10)}`;
            }
            return `movn ${p}${rd}, #${imm16}${hw ? `, lsl #${hw * 16}` : ''}`;
        }
        if (hw !== 0 && imm16 === 0) return `movz ${p}${rd}, #${imm16}, lsl #${hw * 16}`;
        let shiftedVal = BigInt(imm16) << BigInt(hw * 16);
        return `mov ${p}${rd}, #${shiftedVal.toString(10)}`;
    }

    if (matches(value, 0x7f800000, 0x72800000)) {
        let sf = (value >>> 31) & 1, hw = (value >>> 21) & 3, imm16 = (value >>> 5) & 0xffff, rd = value & 0x1f;
        return `movk ${sf ? 'x' : 'w'}${rd}, #${imm16}${hw ? `, lsl #${hw * 16}` : ''}`;
    }

    if (matches(value, 0x7fe0ffe0, 0x2a0003e0)) {
        let sf = (value >>> 31) & 1, rm = (value >>> 16) & 0x1f, rd = value & 0x1f;
        let p = sf ? 'x' : 'w';
        return `mov ${reg(p, rd)}, ${reg(p, rm)}`;
    }

    if (matches(value, 0x1f200000, 0x0b000000)) {
        let sf = (value >>> 31) & 1, op = (value >>> 30) & 1, s = (value >>> 29) & 1;
        let shift = (value >>> 22) & 3, rm = (value >>> 16) & 0x1f, imm6 = (value >>> 10) & 0x3f;
        let rn = (value >>> 5) & 0x1f, rd = value & 0x1f, p = sf ? 'x' : 'w';
        let sh = imm6 ? `, ${['lsl', 'lsr', 'asr', 'ror'][shift]} #${imm6}` : '';
        if (s && rd === 31) {
            return `${op ? 'cmp' : 'cmn'} ${reg(p, rn)}, ${reg(p, rm)}${sh}`;
        }
        if (op && rn === 31) {
            return `${s ? 'negs' : 'neg'} ${p}${rd}, ${reg(p, rm)}${sh}`;
        }
        return `${op ? 'sub' : 'add'}${s ? 's' : ''} ${p}${rd}, ${reg(p, rn)}, ${reg(p, rm)}${sh}`;
    }

    if (matches(value, 0x7f20001f, 0x6b00001f)) {
        let sf = (value >>> 31) & 1, shift = (value >>> 22) & 3, rm = (value >>> 16) & 0x1f;
        let imm6 = (value >>> 10) & 0x3f, rn = (value >>> 5) & 0x1f, p = sf ? 'x' : 'w';
        let sh = imm6 ? `, ${['lsl', 'lsr', 'asr', 'ror'][shift]} #${imm6}` : '';
        return `cmp ${p}${rn}, ${p}${rm}${sh}`;
    }

    { let d = decodeLogicalShiftedReg(value); if (d) return d; }

    { let d = decodeCondSelect(value); if (d) return d; }
    { let d = decodeCondCompare(value); if (d) return d; }
    { let d = decodeLoadStoreRegOffset(value); if (d) return d; }
    { let d = decodeLoadStorePairSimd(value); if (d) return d; }
    { let d = decodeBarrier(value); if (d) return d; }
    { let d = decodeMsrImm(value); if (d) return d; }
    { let d = decodeDcIc(value); if (d) return d; }
    { let d = decodeCrc32(value); if (d) return d; }
    { let d = decodeCas(value); if (d) return d; }
    { let d = decodeSwp(value); if (d) return d; }
    { let d = decodeAtomic(value); if (d) return d; }
    { let d = decodeFmov(value); if (d) return d; }
    { let d = decodeLoadStoreSimdUnsigned(value); if (d) return d; }
    { let d = decodeLoadStoreSimdUnscaled(value); if (d) return d; }
    { let d = decodeLoadStoreSimdRegOffset(value); if (d) return d; }
    { let d = decodeLoadLiteralSimd(value); if (d) return d; }
    { let d = decodeFp2Source(value); if (d) return d; }
    { let d = decodeFpCompare(value); if (d) return d; }
    { let d = decodeFcCmp(value); if (d) return d; }
    { let d = decodeFcSel(value); if (d) return d; }
    { let d = decodeFpImmediate(value); if (d) return d; }
    { let d = decodeFp3Source(value); if (d) return d; }
    { let d = decodeLogicalImm(value); if (d) return d; }
    { let d = decodeBitfield(value); if (d) return d; }
    { let d = decodeDataProc3Source(value); if (d) return d; }
    { let d = decodeBrk(value); if (d) return d; }
    { let d = decodeDataProc2Source(value); if (d) return d; }
    { let d = decodeExtr(value); if (d) return d; }
    { let d = decodeDataProc1SourceBit(value); if (d) return d; }
    { let d = decodeLoadStoreExclusive(value); if (d) return d; }
    { let d = decodeAddSubExtended(value); if (d) return d; }
    { let d = decodeAddSubCarry(value); if (d) return d; }
    { let d = decodeAdvSimdCopyInsElement(value); if (d) return d; }
    { let d = decodeAdvSimdCopy(value); if (d) return d; }
    { let d = decodeAdvSimdScalarCopy(value); if (d) return d; }
    { let d = decodeDupGeneral(value); if (d) return d; }
    { let d = decodeSimdScalarCvtf(value); if (d) return d; }
    { let d = decodeSimdModifiedImm(value); if (d) return d; }
    { let d = decodeAdvSimd3Same(value); if (d) return d; }
    { let d = decodeAdvSimd2RegMisc(value); if (d) return d; }
    { let d = decodeAdvSimd3Different(value); if (d) return d; }
    { let d = decodeAdvSimdDot(value); if (d) return d; }
    { let d = decodeAdvSimdVectorByElement(value); if (d) return d; }
    { let d = decodeAdvSimdScalarByElement(value); if (d) return d; }
    { let d = decodeAdvSimdLdStMultiple(value); if (d) return d; }
    { let d = decodeAdvSimdLdStSingle(value); if (d) return d; }
    { let d = decodeAdvSimdShiftByImm(value); if (d) return d; }
    { let d = decodeAdvSimdScalarShiftByImm(value); if (d) return d; }
    { let d = decodeAdvSimdPermute(value); if (d) return d; }
    { let d = decodeAdvSimdTblTbx(value); if (d) return d; }
    { let d = decodeAdvSimdExt(value); if (d) return d; }
    { let d = decodeAdvSimdAcrossLanes(value); if (d) return d; }
    { let d = decodeAdvSimdScalar3Same(value); if (d) return d; }
    { let d = decodeAdvSimdScalar2RegMisc(value); if (d) return d; }
    { let d = decodeAdvSimdScalarPairwise(value); if (d) return d; }
    { let d = decodeFp1Source(value); if (d) return d; }
    { let d = decodeFpConvertIntFp(value); if (d) return d; }
    { let d = decodeFpConvertFixed(value); if (d) return d; }

    if (matches(value, 0x3b000000, 0x39000000)) {
        let decoded = decodeLoadStoreUnsigned(value);
        if (decoded) return decoded;
    }

    if (matches(value, 0x3b200000, 0x38000000)) {
        let decoded = decodeLoadStoreSigned(value);
        if (decoded) return decoded;
    }

    if (matches(value, 0x3b000000, 0x18000000)) {
        let opc = (value >>> 30) & 3;
        if (opc === 0 || opc === 1) {
            let off = signExtend((value >>> 5) & 0x7ffff, 19) << 2;
            return `ldr ${opc === 1 ? 'x' : 'w'}${value & 0x1f}, ${immStr(off)}`;
        }
        if (opc === 2) {
            let off = signExtend((value >>> 5) & 0x7ffff, 19) << 2;
            return `ldrsw x${value & 0x1f}, ${immStr(off)}`;
        }
    }

    if (matches(value, 0x3b800000, 0x28000000)) {
        let opc = (value >>> 30) & 3, v = (value >>> 26) & 1, l = (value >>> 22) & 1;
        let imm7 = signExtend((value >>> 15) & 0x7f, 7), rt2 = (value >>> 10) & 0x1f, rn = (value >>> 5) & 0x1f, rt = value & 0x1f;
        let rnReg = rn === 31 ? 'sp' : `x${rn}`;
        let mnem = l ? 'ldnp' : 'stnp';
        if (v) {
            let p = opc === 0 ? 's' : opc === 1 ? 'd' : 'q';
            let scale = opc === 0 ? 2 : opc === 1 ? 3 : 4;
            let off = imm7 << scale;
            let addr = `[${rnReg}${off ? `, ${immStr(off)}` : ''}]`;
            return `${mnem} ${p}${rt}, ${p}${rt2}, ${addr}`;
        }
        if (opc === 1) return null;
        let is64 = opc === 2, p = is64 ? 'x' : 'w', off = imm7 << (is64 ? 3 : 2);
        let addr = `[${rnReg}${off ? `, ${immStr(off)}` : ''}]`;
        return `${mnem} ${reg(p, rt)}, ${reg(p, rt2)}, ${addr}`;
    }

    if (matches(value, 0x3b800000, 0x28800000) || matches(value, 0x3b800000, 0x29000000) || matches(value, 0x3b800000, 0x29800000)) {
        let opc = (value >>> 30) & 3, v = (value >>> 26) & 1, l = (value >>> 22) & 1;
        if (!v) {
            let imm7 = signExtend((value >>> 15) & 0x7f, 7), rt2 = (value >>> 10) & 0x1f, rn = (value >>> 5) & 0x1f, rt = value & 0x1f;
            let mode = (value >>> 23) & 3;
            let rnReg = rn === 31 ? 'sp' : `x${rn}`;
            if (opc === 1) {
                if (!l) return null;
                let off = imm7 << 2;
                let addr = mode === 1 ? `[${rnReg}], ${immStr(off)}` : mode === 3 ? `[${rnReg}, ${immStr(off)}]!` : `[${rnReg}${off ? `, ${immStr(off)}` : ''}]`;
                return `ldpsw x${rt}, x${rt2}, ${addr}`;
            }
            let is64 = opc === 2, p = is64 ? 'x' : 'w', off = imm7 << (is64 ? 3 : 2);
            let addr = mode === 1 ? `[${rnReg}], ${immStr(off)}` : mode === 3 ? `[${rnReg}, ${immStr(off)}]!` : `[${rnReg}${off ? `, ${immStr(off)}` : ''}]`;
            return `${l ? 'ldp' : 'stp'} ${reg(p, rt)}, ${reg(p, rt2)}, ${addr}`;
        }
    }

    if (matches(value, 0xfc000000, 0x14000000) || matches(value, 0xfc000000, 0x94000000)) {
        let off = signExtend(value & 0x3ffffff, 26) << 2;
        return `${matches(value, 0xfc000000, 0x94000000) ? 'bl' : 'b'} ${immStr(off)}`;
    }

    if (matches(value, 0xff000010, 0x54000000)) {
        let cond = value & 0xf, off = signExtend((value >>> 5) & 0x7ffff, 19) << 2;
        return `b.${condNames[cond]} ${immStr(off)}`;
    }

    if (matches(value, 0x7e000000, 0x34000000)) {
        let sf = (value >>> 31) & 1, op = (value >>> 24) & 1, off = signExtend((value >>> 5) & 0x7ffff, 19) << 2;
        return `${op ? 'cbnz' : 'cbz'} ${sf ? 'x' : 'w'}${value & 0x1f}, ${immStr(off)}`;
    }

    if (matches(value, 0x7e000000, 0x36000000)) {
        let b5 = (value >>> 31) & 1, op = (value >>> 24) & 1, b40 = (value >>> 19) & 0x1f;
        let off = signExtend((value >>> 5) & 0x3fff, 14) << 2;
        return `${op ? 'tbnz' : 'tbz'} ${b5 ? 'x' : 'w'}${value & 0x1f}, #${(b5 << 5) | b40}, ${immStr(off)}`;
    }

    return 'Unknown instruction';
}

function requireRange(value, bits, signed, context) {
    let lo = signed ? -(1 << (bits - 1)) : 0;
    let hi = signed ? (1 << (bits - 1)) - 1 : (Math.pow(2, bits) - 1);
    if (value < lo || value > hi) {
        throw new Error(`Immediate out of range for ${context}: ${value} (expected ${lo}..${hi})`);
    }
    return value;
}

function requireAligned(value, align, context) {
    if (value % align !== 0) {
        throw new Error(`Immediate must be ${align}-byte aligned for ${context}: ${value}`);
    }
    return value;
}

function encodeBitMasks(patternBig, is64) {
    let width = is64 ? 64 : 32;
    let fullMask = (1n << BigInt(width)) - 1n;
    let pattern = patternBig & fullMask;
    if (pattern === 0n || pattern === fullMask) {
        throw new Error('Logical immediate cannot be all-zero or all-one bits');
    }
    const sizes = is64 ? [64, 32, 16, 8, 4, 2] : [32, 16, 8, 4, 2];
    for (let size of sizes) {
        let elemMask = (1n << BigInt(size)) - 1n;
        let elem = pattern & elemMask;

        let ok = true;
        for (let i = 0; i < width; i += size) {
            if (((pattern >> BigInt(i)) & elemMask) !== elem) { ok = false; break; }
        }
        if (!ok) continue;

        for (let rot = 0; rot < size; rot++) {
            let rotated = ((elem >> BigInt(rot)) | (elem << BigInt(size - rot))) & elemMask;

            if (rotated === 0n) continue;
            let plus1 = rotated + 1n;
            let isRun = (plus1 & (plus1 - 1n)) === 0n;
            if (isRun) {
                let ones = 0n, t = rotated;
                while (t & 1n) { ones++; t >>= 1n; }

                let S = Number(ones) - 1;
                let immr = (rot === 0) ? 0 : (size - rot);
                let N = (size === 64) ? 1 : 0;
                let topBits = (~((size << 1) - 1)) & 0x3f;
                let imms = (topBits | S) & 0x3f;

                let check = decodeBitMasks(N, immr & 0x3f, imms, is64);
                if (check !== null && check === pattern) {
                    return { N, immr: immr & 0x3f, imms };
                }
            }
        }
    }
    throw new Error('Value cannot be encoded as a logical immediate');
}

function encRet(mnemonic, ops) {
    return ops[0] ? (0xd65f0000 | (parseReg(ops[0]).num << 5)) : 0xd65f03c0;
}
function encBr(mnemonic, ops) {
    return 0xd61f0000 | (parseReg(ops[0]).num << 5);
}
function encBlr(mnemonic, ops) {
    return 0xd63f0000 | (parseReg(ops[0]).num << 5);
}
function encBrk(mnemonic, ops) {
    let imm16 = requireRange(parseImm(ops[0]), 16, false, 'brk');
    return 0xd4200000 | (imm16 << 5);
}
function encSvc(mnemonic, ops) {
    return 0xd4000001 | (requireRange(parseImm(ops[0]), 16, false, 'svc') << 5);
}
function encBarrier(mnemonic, ops) {
    const barrierOpts = {
        sy: 15, st: 14, ld: 13, ish: 11, ishst: 10, ishld: 9,
        nsh: 7, nshst: 6, nshld: 5, osh: 3, oshst: 2, oshld: 1
    };
    let opt = ops[0].toLowerCase();
    let crm = barrierOpts[opt];
    if (crm === undefined) crm = requireRange(parseImm(opt), 4, false, mnemonic);
    let op2 = mnemonic === 'dsb' ? 4 : 5;
    return 0xd503309f | (crm << 8) | (op2 << 5);
}
function encClrex(mnemonic, ops) {
    if (!ops[0]) return 0xd5033f5f;
    let crm = requireRange(parseImm(ops[0]), 4, false, 'clrex');
    return (0xd5033f5f & ~0xf00) | (crm << 8);
}
function encIsb() {
    return 0xd5033fdf;
}
function encCrc32(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]), rm = parseReg(ops[2]);
    let c = mnemonic.startsWith('crc32c') ? 1 : 0;
    let sizeChar = mnemonic.slice(-1);
    let sz = { b: 0, h: 1, w: 2, x: 3 }[sizeChar];
    let sf = sz === 3 ? 1 : 0;
    return (sf << 31) | 0x1ac04000 | (rm.num << 16) | (c << 12) | (sz << 10) | (rn.num << 5) | rd.num;
}
function encLdapr(mnemonic, ops) {
    let rt = parseReg(ops[0]);
    let memMatch = ops[1].match(/^\[(sp|x\d+)\]$/);
    if (!memMatch) throw new Error(`Unsupported address mode for ${mnemonic}: ${ops[1]}`);
    let rn = memMatch[1] === 'sp' ? 31 : parseReg(memMatch[1]).num;
    let sizeSuf = mnemonic.match(/[bh]$/);
    let size = sizeSuf ? (sizeSuf[0] === 'b' ? 0 : 1) : (rt.size === 64 ? 3 : 2);
    return ((size << 30) | (0x38 << 24) | (1 << 23) | (1 << 21) | (0x1f << 16) | (1 << 15) | (4 << 12) | (rn << 5) | rt.num) >>> 0;
}
function encCas(mnemonic, ops) {
    let rs = parseReg(ops[0]), rt = parseReg(ops[1]);
    let memMatch = ops[2].match(/^\[(sp|x\d+)\]$/);
    if (!memMatch) throw new Error(`Unsupported address mode for ${mnemonic}: ${ops[2]}`);
    let rn = memMatch[1] === 'sp' ? 31 : parseReg(memMatch[1]).num;
    let sizeSuf = mnemonic.match(/[bh]$/);
    let size = sizeSuf ? (sizeSuf[0] === 'b' ? 0 : 1) : (rt.size === 64 ? 3 : 2);
    let baseName = sizeSuf ? mnemonic.slice(0, -1) : mnemonic;
    let l = (baseName === 'casa' || baseName === 'casal') ? 1 : 0;
    let o0 = (baseName === 'casl' || baseName === 'casal') ? 1 : 0;
    return (size << 30) | 0x08a07c00 | (l << 22) | (rs.num << 16) | (o0 << 15) | (rn << 5) | rt.num;
}
function encSwp(mnemonic, ops) {
    let rs = parseReg(ops[0]), rt = parseReg(ops[1]);
    let memMatch = ops[2].match(/^\[(sp|x\d+)\]$/);
    if (!memMatch) throw new Error(`Unsupported address mode for ${mnemonic}: ${ops[2]}`);
    let rn = memMatch[1] === 'sp' ? 31 : parseReg(memMatch[1]).num;
    let m = mnemonic.match(/^swp(a|l|al)?([bh])?$/);
    let suffix = m[1] || '', sizeSuf = m[2];
    let size = sizeSuf ? (sizeSuf === 'b' ? 0 : 1) : (rt.size === 64 ? 3 : 2);
    let a = suffix.includes('a') ? 1 : 0, l = suffix.includes('l') ? 1 : 0;
    return (size << 30) | 0x38208000 | (a << 23) | (l << 22) | (rs.num << 16) | (rn << 5) | rt.num;
}
function encAtomicLd(mnemonic, ops) {
    let rs = parseReg(ops[0]), rt = parseReg(ops[1]);
    let memMatch = ops[2].match(/^\[(sp|x\d+)\]$/);
    if (!memMatch) throw new Error(`Unsupported address mode for ${mnemonic}: ${ops[2]}`);
    let rn = memMatch[1] === 'sp' ? 31 : parseReg(memMatch[1]).num;
    let m = mnemonic.match(/^ld(add|clr|eor|set|smax|smin|umax|umin)(a|l|al)?([bh])?$/);
    let op = m[1], suffix = m[2] || '', sizeSuf = m[3];
    const opcMap = { add: 0, clr: 1, eor: 2, set: 3, smax: 4, smin: 5, umax: 6, umin: 7 };
    let size = sizeSuf ? (sizeSuf === 'b' ? 0 : 1) : (rt.size === 64 ? 3 : 2);
    let a = suffix.includes('a') ? 1 : 0, r = suffix.includes('l') ? 1 : 0;
    return (size << 30) | 0x38200000 | (a << 23) | (r << 22) | (rs.num << 16) | (opcMap[op] << 12) | (rn << 5) | rt.num;
}
function encMrsMsr(mnemonic, ops) {
    if (mnemonic === 'msr' && /^(daifset|daifclr|spsel)$/i.test(ops[0]) && ops[1] && ops[1].startsWith('#')) {
        const pstateFields = { spsel: [0, 5], daifset: [3, 6], daifclr: [3, 7] };
        let [op1, op2] = pstateFields[ops[0].toLowerCase()];
        let crm = requireRange(parseImm(ops[1]), 4, false, mnemonic);
        return 0xd500401f | (op1 << 16) | (crm << 8) | (op2 << 5);
    }
    if (mnemonic === 'mrs') {
        let rt = parseReg(ops[0]);
        let sysName = ops[1];
        let base = systemRegToEncoding[sysName];
        if (base === undefined) {
            let fields = genericSysRegToFields(sysName);
            if (fields === null) throw new Error(`Unsupported system register: ${sysName}`);
            base = 0xd5300000 | fields;
        }
        return base | rt.num;
    }

    let sysName = ops[0];
    let rt = parseReg(ops[1]);
    let base = systemRegToEncoding[sysName];
    let fields;
    if (base !== undefined) {
        fields = base & 0x1fffe0;
    } else {
        fields = genericSysRegToFields(sysName);
        if (fields === null) throw new Error(`Unsupported system register: ${sysName}`);
    }
    return 0xd5100000 | fields | rt.num;
}
function encBranch(mnemonic, ops) {
    let imm = parseImm(ops[0]);
    requireAligned(imm, 4, mnemonic);
    let off = imm >> 2;
    requireRange(off, 26, true, mnemonic);
    return (mnemonic === 'bl' ? 0x94000000 : 0x14000000) | (off & 0x3ffffff);
}
function encBCond(mnemonic, ops) {
    let cond = condNames.indexOf(mnemonic.slice(2));
    if (cond < 0) throw new Error(`Bad condition: ${mnemonic}`);
    let imm = parseImm(ops[0]);
    requireAligned(imm, 4, mnemonic);
    let off = imm >> 2;
    requireRange(off, 19, true, mnemonic);
    return 0x54000000 | ((off & 0x7ffff) << 5) | cond;
}
function encAdr(mnemonic, ops) {
    let rd = parseReg(ops[0]).num;
    let imm = parseImm(ops[1]);
    if (mnemonic === 'adrp') {
        requireAligned(imm, 4096, 'adrp');
        imm = imm / 4096;
        requireRange(imm, 21, true, 'adrp');
    } else {
        requireRange(imm, 21, true, 'adr');
    }
    return (mnemonic === 'adrp' ? 0x90000000 : 0x10000000) |
        ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5) | rd;
}
function encMovWide(mnemonic, ops) {
    let rd = parseReg(ops[0]), imm = parseImm(ops[1]), hw = 0;
    if (ops[2]) hw = parseImm(ops[2].replace(/^lsl\s+/, '')) / 16;
    requireRange(imm, 16, false, mnemonic);
    if (![0, 1, 2, 3].includes(hw) || (rd.size === 32 && hw > 1)) {
        throw new Error(`Bad lsl shift for ${mnemonic}: #${hw * 16}`);
    }
    let base = mnemonic === 'movn' ? 0x12800000 : mnemonic === 'movk' ? 0x72800000 : 0x52800000;
    return ((rd.size === 64 ? 1 : 0) << 31) | base | ((hw & 3) << 21) | ((imm & 0xffff) << 5) | rd.num;
}
function encMov(mnemonic, ops, instruction, littleEndian) {
    let rd = parseReg(ops[0]);
    if (ops[1].startsWith('#')) {
        let is64 = rd.size === 64;
        let width = is64 ? 64 : 32;
        let raw = parseImm(ops[1]);
        let mask = is64 ? (2n ** 64n - 1n) : 0xffffffffn;
        let uval = (BigInt(raw) & mask);

        for (let hw = 0; hw < width / 16; hw++) {
            let chunk = (uval >> BigInt(hw * 16)) & 0xffffn;
            let rest = uval & ~(0xffffn << BigInt(hw * 16)) & mask;
            if (rest === 0n) {
                let shiftStr = hw ? `, lsl #${hw * 16}` : '';
                return encodeArm64(`movz ${ops[0]}, #${chunk}${shiftStr}`, littleEndian);
            }
        }

        let notVal = (~uval) & mask;
        for (let hw = 0; hw < width / 16; hw++) {
            let chunk = (notVal >> BigInt(hw * 16)) & 0xffffn;
            let rest = notVal & ~(0xffffn << BigInt(hw * 16)) & mask;
            if (rest === 0n) {
                let shiftStr = hw ? `, lsl #${hw * 16}` : '';
                return encodeArm64(`movn ${ops[0]}, #${chunk}${shiftStr}`, littleEndian);
            }
        }

        let zr = is64 ? 'xzr' : 'wzr';
        return encodeArm64(`orr ${ops[0]}, ${zr}, #${uval}`, littleEndian);
    }
    let rm = parseReg(ops[1]);
    if (rd.sp || rm.sp) {

        let p = rd.size === 64 ? 'x' : 'w';
        let rdName = rd.sp ? (rd.size === 64 ? 'sp' : 'wsp') : `${p}${rd.num}`;
        let rnName = rm.sp ? (rm.size === 64 ? 'sp' : 'wsp') : `${p}${rm.num}`;
        return encodeArm64(`add ${rdName}, ${rnName}, #0`, littleEndian);
    }
    return ((rd.size === 64 ? 1 : 0) << 31) | (rd.size === 64 ? 0xaa0003e0 : 0x2a0003e0) | (rm.num << 16) | rd.num;
}
function encCondAlias(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]);
    let cond = condNames.indexOf(ops[2]);
    if (cond < 0) throw new Error(`Bad condition: ${ops[2]}`);
    let invCond = cond ^ 1;
    let op, op2;
    if (mnemonic === 'cinc') { op = 0; op2 = 1; }
    else if (mnemonic === 'cinv') { op = 1; op2 = 0; }
    else { op = 1; op2 = 1; }
    return ((rd.size === 64 ? 1 : 0) << 31) | (op << 30) | 0x1a800000 | (rn.num << 16) | (invCond << 12) | (op2 << 10) | (rn.num << 5) | rd.num;
}
function encCset(mnemonic, ops) {
    let rd = parseReg(ops[0]);
    let cond = condNames.indexOf(ops[1]);
    if (cond < 0) throw new Error(`Bad condition: ${ops[1]}`);
    let invCond = cond ^ 1;
    let op2 = mnemonic === 'cset' ? 1 : 0;
    let op = mnemonic === 'cset' ? 0 : 1;
    return ((rd.size === 64 ? 1 : 0) << 31) | (op << 30) | 0x1a800000 | (31 << 16) | (invCond << 12) | (op2 << 10) | (31 << 5) | rd.num;
}
function encCsel(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]), rm = parseReg(ops[2]);
    let cond = condNames.indexOf(ops[3]);
    if (cond < 0) throw new Error(`Bad condition: ${ops[3]}`);
    let op = (mnemonic === 'csinv' || mnemonic === 'csneg') ? 1 : 0;
    let op2 = (mnemonic === 'csinc' || mnemonic === 'csneg') ? 1 : 0;
    return ((rd.size === 64 ? 1 : 0) << 31) | (op << 30) | 0x1a800000 | (rm.num << 16) | (cond << 12) | (op2 << 10) | (rn.num << 5) | rd.num;
}
function encCcmp(mnemonic, ops) {
    let rn = parseReg(ops[0]);
    let cond = condNames.indexOf(ops[3]);
    if (cond < 0) throw new Error(`Bad condition: ${ops[3]}`);
    let nzcv = parseImm(ops[2]);
    let op = mnemonic === 'ccmp' ? 1 : 0;
    let imm = ops[1].startsWith('#') ? 1 : 0;
    let y = imm ? (parseImm(ops[1]) & 0x1f) : parseReg(ops[1]).num;
    return ((rn.size === 64 ? 1 : 0) << 31) | (op << 30) | 0x3a400000 | (y << 16) | (cond << 12) | (imm << 11) | (rn.num << 5) | nzcv;
}
function encAdcSbc(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]), rm = parseReg(ops[2]);
    let op = mnemonic.startsWith('sbc') ? 1 : 0, s = mnemonic.endsWith('s') ? 1 : 0;
    return ((rd.size === 64 ? 1 : 0) << 31) | (op << 30) | (s << 29) | 0x1a000000 | (rm.num << 16) | (rn.num << 5) | rd.num;
}
function encNgc(mnemonic, ops) {
    let rd = parseReg(ops[0]), rm = parseReg(ops[1]);
    let s = mnemonic === 'ngcs' ? 1 : 0;
    return ((rd.size === 64 ? 1 : 0) << 31) | (1 << 30) | (s << 29) | 0x1a000000 | (rm.num << 16) | (31 << 5) | rd.num;
}
function encDataProc2Source(mnemonic, ops) {

    let rd = parseReg(ops[0]), rn = parseReg(ops[1]), rm = parseReg(ops[2]);
    const opcodes = { udiv: 2, sdiv: 3, lslv: 8, lsl: 8, lsrv: 9, lsr: 9, asrv: 10, asr: 10, rorv: 11, ror: 11 };
    return ((rd.size === 64 ? 1 : 0) << 31) | 0x1ac00000 | (rm.num << 16) | (opcodes[mnemonic] << 10) | (rn.num << 5) | rd.num;
}
function encMul3Source(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]), rm = parseReg(ops[2]);
    let ra = ops[3] ? parseReg(ops[3]).num : 31;
    let o0 = (mnemonic === 'msub' || mnemonic === 'mneg') ? 1 : 0;
    return ((rd.size === 64 ? 1 : 0) << 31) | 0x1b000000 | (rm.num << 16) | (o0 << 15) | (ra << 10) | (rn.num << 5) | rd.num;
}
function encMulLong(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]), rm = parseReg(ops[2]);
    let ra = ops[3] ? parseReg(ops[3]).num : 31;
    let isU = mnemonic.startsWith('u');
    let op31 = isU ? 5 : 1;
    let o0 = (mnemonic.endsWith('subl') || mnemonic.endsWith('negl')) ? 1 : 0;
    return (1 << 31) | 0x1b000000 | (op31 << 21) | (rm.num << 16) | (o0 << 15) | (ra << 10) | (rn.num << 5) | rd.num;
}
function encMulh(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]), rm = parseReg(ops[2]);
    let op31 = mnemonic === 'smulh' ? 2 : 6;
    return (1 << 31) | 0x1b000000 | (op31 << 21) | (rm.num << 16) | (31 << 10) | (rn.num << 5) | rd.num;
}
function encDataProc1SourceBit(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]);
    let opcode;
    if (mnemonic === 'rbit') opcode = 0;
    else if (mnemonic === 'rev16') opcode = 1;
    else if (mnemonic === 'rev32') {
        if (rd.size !== 64) throw new Error('rev32 requires a 64-bit (x) register');
        opcode = 2;
    }
    else if (mnemonic === 'rev' || mnemonic === 'rev64') opcode = rd.size === 64 ? 3 : 2;
    else if (mnemonic === 'clz') opcode = 4;
    else opcode = 5;
    return ((rd.size === 64 ? 1 : 0) << 31) | 0x5ac00000 | (opcode << 10) | (rn.num << 5) | rd.num;
}
function encLoadStoreExclusive(mnemonic, ops) {

    const table = {
        ldxr: { L: 1, o1: 0, o0: 0 }, ldaxr: { L: 1, o1: 0, o0: 1 },
        stxr: { L: 0, o1: 0, o0: 0 }, stlxr: { L: 0, o1: 0, o0: 1 },
        ldxp: { L: 1, o1: 1, o0: 0 }, ldaxp: { L: 1, o1: 1, o0: 1 },
        stxp: { L: 0, o1: 1, o0: 0 }, stlxp: { L: 0, o1: 1, o0: 1 },
        ldar: { L: 1, o2: 1, o0: 1 }, stlr: { L: 0, o2: 1, o0: 1 },
        ldlar: { L: 1, o2: 1, o0: 0 }, stllr: { L: 0, o2: 1, o0: 0 },
    };
    let m = mnemonic.match(/^(ldxr|ldaxr|stxr|stlxr|ldxp|ldaxp|stxp|stlxp|ldar|stlr|ldlar|stllr)([bh])?$/);
    if (!m) throw new Error(`Unsupported instruction: ${mnemonic}`);
    let base = m[1], sizeSuf = m[2];
    let info = table[base];
    let isPair = base === 'ldxp' || base === 'ldaxp' || base === 'stxp' || base === 'stlxp';
    let isStore = base.startsWith('st');

    let rs = 31, rt, rt2Num = 31, memOp;
    if (isPair) {
        if (isStore) { rs = parseReg(ops[0]).num; rt = parseReg(ops[1]); rt2Num = parseReg(ops[2]).num; memOp = ops[3]; }
        else { rt = parseReg(ops[0]); rt2Num = parseReg(ops[1]).num; memOp = ops[2]; }
    } else if (isStore && info.o2 !== 1) {
        rs = parseReg(ops[0]).num; rt = parseReg(ops[1]); memOp = ops[2];
    } else {
        rt = parseReg(ops[0]); memOp = ops[1];
    }
    let memMatch = memOp.match(/^\[(sp|x\d+)\]$/);
    if (!memMatch) throw new Error(`Unsupported address mode for ${mnemonic}: ${memOp}`);
    let rn = memMatch[1] === 'sp' ? 31 : parseReg(memMatch[1]).num;

    let size = sizeSuf ? (sizeSuf === 'b' ? 0 : 1) : (rt.size === 64 ? 3 : 2);
    let o2 = info.o2 || 0, L = info.L, o1 = info.o1 || 0, o0 = info.o0;
    return (size << 30) | 0x08000000 | (o2 << 23) | (L << 22) | (o1 << 21) |
        (rs << 16) | (o0 << 15) | (rt2Num << 10) |
        (rn << 5) | rt.num;
}
function encExtr(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]), rm = parseReg(ops[2]), lsb = parseImm(ops[3]);
    let is64 = rd.size === 64;
    requireRange(lsb, is64 ? 6 : 5, false, 'extr');
    return ((is64 ? 1 : 0) << 31) | 0x13800000 | ((is64 ? 1 : 0) << 22) | (rm.num << 16) | (lsb << 10) | (rn.num << 5) | rd.num;
}
function encRorImm(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]), imm = parseImm(ops[2]);
    let is64 = rd.size === 64;
    requireRange(imm, is64 ? 6 : 5, false, 'ror');
    return ((is64 ? 1 : 0) << 31) | 0x13800000 | ((is64 ? 1 : 0) << 22) | (rn.num << 16) | (imm << 10) | (rn.num << 5) | rd.num;
}
function encShiftImm(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]), amt = parseImm(ops[2]);
    let is64 = rd.size === 64, regSize = is64 ? 64 : 32;
    requireRange(amt, is64 ? 6 : 5, false, mnemonic);
    let N = is64 ? 1 : 0, opc, immr, imms;
    if (mnemonic === 'lsl') { opc = 2; immr = (regSize - amt) % regSize; imms = regSize - 1 - amt; }
    else if (mnemonic === 'lsr') { opc = 2; immr = amt; imms = regSize - 1; }
    else { opc = 0; immr = amt; imms = regSize - 1; }
    return ((is64 ? 1 : 0) << 31) | (opc << 29) | 0x13000000 | (N << 22) | (immr << 16) | (imms << 10) | (rn.num << 5) | rd.num;
}
function encBitfieldRaw(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]);
    let immr = parseImm(ops[2]), imms = parseImm(ops[3]);
    let is64 = rd.size === 64, regSize = is64 ? 64 : 32;
    requireRange(immr, is64 ? 6 : 5, false, mnemonic);
    requireRange(imms, is64 ? 6 : 5, false, mnemonic);
    let N = is64 ? 1 : 0;
    const opcMap = { sbfm: 0, bfm: 1, ubfm: 2 };
    let opc = opcMap[mnemonic];
    return ((is64 ? 1 : 0) << 31) | (opc << 29) | 0x13000000 | (N << 22) | (immr << 16) | (imms << 10) | (rn.num << 5) | rd.num;
}
function encBitfield(mnemonic, ops) {
    let isBfc = mnemonic === 'bfc';
    let rd = parseReg(ops[0]);
    let rn = isBfc ? { num: 31, size: rd.size } : parseReg(ops[1]);
    let lsb = parseImm(ops[isBfc ? 1 : 2]);
    let width = parseImm(ops[isBfc ? 2 : 3]);
    let is64 = rd.size === 64, regSize = is64 ? 64 : 32;
    if (!(width >= 1 && width <= 64)) throw new Error(`Bitfield width out of range for ${mnemonic}: ${width} (expected 1..64)`);
    if (!(lsb >= 0 && lsb + width <= regSize)) throw new Error(`Bitfield lsb+width out of range for ${mnemonic}: ${lsb}+${width} (expected 0..${regSize})`);
    let N = is64 ? 1 : 0, opc, immr, imms;
    let isFizFamily = mnemonic === 'sbfiz' || mnemonic === 'ubfiz' || mnemonic === 'bfi' || isBfc;
    if (isFizFamily) {
        immr = (regSize - lsb) % regSize;
        imms = width - 1;
    } else {
        immr = lsb;
        imms = lsb + width - 1;
    }
    if (mnemonic === 'sbfx' || mnemonic === 'sbfiz') opc = 0;
    else if (mnemonic === 'ubfx' || mnemonic === 'ubfiz') opc = 2;
    else opc = 1;
    return ((is64 ? 1 : 0) << 31) | (opc << 29) | 0x13000000 | (N << 22) | (immr << 16) | (imms << 10) | (rn.num << 5) | rd.num;
}
function encExtend(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]);
    let bits = mnemonic.endsWith('b') ? 7 : mnemonic.endsWith('h') ? 15 : 31;
    let isSigned = mnemonic.startsWith('s');
    let N = rd.size === 64 ? 1 : 0, opc = isSigned ? 0 : 2;
    return ((rd.size === 64 ? 1 : 0) << 31) | (opc << 29) | 0x13000000 | (N << 22) | (0 << 16) | (bits << 10) | (rn.num << 5) | rd.num;
}
function encArithExtended(mnemonic, ops) {

    let cmpLike = mnemonic === 'cmp' || mnemonic === 'cmn';
    let rd = cmpLike ? null : parseReg(ops[0]);
    let rn = parseReg(ops[cmpLike ? 0 : 1]);
    let rmOp = ops[cmpLike ? 1 : 2];
    let rm = parseReg(rmOp);
    let is64 = cmpLike ? rn.size === 64 : rd.size === 64;
    let extOp = ops[ops.length - 1];
    let m = (extOp !== rmOp) ? extOp.match(/^(uxtb|uxth|uxtw|uxtx|sxtb|sxth|sxtw|sxtx)(?:\s+#?(\d+))?$/) : null;
    const extMap = { uxtb: 0, uxth: 1, uxtw: 2, uxtx: 3, sxtb: 4, sxth: 5, sxtw: 6, sxtx: 7 };
    let option, imm3;
    if (m) {
        option = extMap[m[1]]; imm3 = m[2] ? parseInt(m[2], 10) : 0;
    } else {

        option = is64 ? 3 : 2; imm3 = 0;
    }
    requireRange(imm3, 3, false, mnemonic);
    let op = (mnemonic === 'sub' || mnemonic === 'subs' || mnemonic === 'cmp') ? 1 : 0;
    let s = cmpLike ? 1 : (mnemonic.endsWith('s') ? 1 : 0);
    let rdNum = cmpLike ? 31 : rd.num;
    return ((is64 ? 1 : 0) << 31) | (op << 30) | (s << 29) | 0x0b200000 | (rm.num << 16) | (option << 13) | (imm3 << 10) | (rn.num << 5) | rdNum;
}
function isExtendedRegForm(ops) {
    return ops.length > 0 && /^(uxtb|uxth|uxtw|uxtx|sxtb|sxth|sxtw|sxtx)(\s+#?\d+)?$/.test(ops[ops.length - 1] || '');
}
function encArithOrLogical(mnemonic, ops) {

    const logicalImmSet = ['and', 'orr', 'eor', 'ands', 'tst'];
    if (logicalImmSet.includes(mnemonic) && ops[ops.length - 1] && ops[ops.length - 1].startsWith('#')) {
        return encLogicalImm(mnemonic, ops);
    }
    if (['add', 'adds', 'sub', 'subs'].includes(mnemonic) && ops[2] && ops[2].startsWith('#')) {
        return encArithImm(mnemonic, ops);
    }
    if (mnemonic === 'cmp' && ops[1] && ops[1].startsWith('#')) return encCmpImm(mnemonic, ops);
    if (mnemonic === 'cmn' && ops[1] && ops[1].startsWith('#')) return encCmnImm(mnemonic, ops);

    if (['add', 'adds', 'sub', 'subs', 'cmp', 'cmn'].includes(mnemonic) &&
        (isExtendedRegForm(ops) || /^(sp|wsp)$/i.test(ops[0]) || /^(sp|wsp)$/i.test(ops[mnemonic === 'cmp' || mnemonic === 'cmn' ? 0 : 1]))) {
        return encArithExtended(mnemonic, ops);
    }

    const logicalOpc = { and: 0, bic: 0, orr: 1, orn: 1, mvn: 1, eor: 2, eon: 2, ands: 3, bics: 3, tst: 3 };
    const invertN = { bic: 1, orn: 1, mvn: 1, eon: 1, bics: 1 };
    let isLogical = mnemonic in logicalOpc;
    let cmp = mnemonic === 'cmp';
    let cmn = mnemonic === 'cmn';
    let tst = mnemonic === 'tst';
    let mvn = mnemonic === 'mvn';
    let rd, rn, rm, ops2Idx;
    if (cmp || cmn || tst) { rn = parseReg(ops[0]); rm = parseReg(ops[1]); rd = { num: 31, size: rn.size }; ops2Idx = 2; }
    else if (mvn) { rd = parseReg(ops[0]); rm = parseReg(ops[1]); rn = { num: 31, size: rd.size }; ops2Idx = 2; }
    else { rd = parseReg(ops[0]); rn = parseReg(ops[1]); rm = parseReg(ops[2]); ops2Idx = 3; }
    let shift = 0, imm6 = 0, shiftOp = ops[ops2Idx];
    if (shiftOp) {

        let allowedShifts = isLogical ? /^(lsl|lsr|asr|ror)\s+#?(\d+)$/ : /^(lsl|lsr|asr)\s+#?(\d+)$/;
        let m = shiftOp.match(allowedShifts);
        if (!m) throw new Error(`Bad shift for ${mnemonic}: ${shiftOp}`);
        shift = { lsl: 0, lsr: 1, asr: 2, ror: 3 }[m[1]];
        imm6 = parseInt(m[2], 10);
        requireRange(imm6, rd.size === 64 ? 6 : 5, false, mnemonic);
    }
    if (isLogical) {
        let opc = logicalOpc[mnemonic];
        let N = invertN[mnemonic] || 0;
        return ((rd.size === 64 ? 1 : 0) << 31) | (opc << 29) | 0x0a000000 | (shift << 22) | (N << 21) | (rm.num << 16) | (imm6 << 10) | (rn.num << 5) | rd.num;
    }
    let op = (mnemonic.startsWith('sub') || cmp) ? 1 : 0;
    let s = (mnemonic.endsWith('s') || cmp || cmn) ? 1 : 0;
    return ((rd.size === 64 ? 1 : 0) << 31) | (op << 30) | (s << 29) | 0x0b000000 | (shift << 22) | (rm.num << 16) | (imm6 << 10) | (rn.num << 5) | rd.num;
}
function encLogicalImm(mnemonic, ops) {
    let isTst = mnemonic === 'tst';
    let rd = isTst ? null : parseReg(ops[0]);
    let rn = parseReg(ops[isTst ? 0 : 1]);
    let immStrOp = ops[isTst ? 1 : 2];
    let immStrClean = immStrOp.replace(/^#/, '');
    let immVal = immStrClean.startsWith('-') ? -BigInt(immStrClean.slice(1)) : BigInt(immStrClean);
    let is64 = rn.size === 64;
    if (immVal < 0n) immVal = immVal & ((1n << BigInt(is64 ? 64 : 32)) - 1n);
    let { N, immr, imms } = encodeBitMasks(immVal, is64);
    let opc = isTst ? 3 : { and: 0, orr: 1, eor: 2, ands: 3 }[mnemonic];
    let rdNum = isTst ? 31 : rd.num;
    return ((is64 ? 1 : 0) << 31) | (opc << 29) | 0x12000000 | (N << 22) | (immr << 16) | (imms << 10) | (rn.num << 5) | rdNum;
}
function encArithImm(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseReg(ops[1]), imm = parseImm(ops[2]), sh = 0;
    if (imm < 0) {
        mnemonic = mnemonic.startsWith('sub') ? `add${mnemonic.slice(3)}` : `sub${mnemonic.slice(3)}`;
        imm = -imm;
    }
    if (ops[3]) {
        let m = ops[3].match(/^lsl\s*#?(\d+)$/i);
        if (!m || parseInt(m[1], 10) !== 12) throw new Error(`Unsupported shift for ${mnemonic}: ${ops[3]}`);
        sh = 1;
    } else if (imm > 0xfff) {
        if ((imm & 0xfff) !== 0) throw new Error(`add/sub immediate out of range (12-bit, optionally <<12): ${imm}`);
        sh = 1; imm = imm / 4096;
    }
    requireRange(imm, 12, false, mnemonic);
    return ((rd.size === 64 ? 1 : 0) << 31) | (mnemonic.startsWith('sub') ? 1 << 30 : 0) |
        (mnemonic.endsWith('s') ? 1 << 29 : 0) | 0x11000000 | (sh << 22) |
        ((imm & 0xfff) << 10) | (rn.num << 5) | rd.num;
}
function encCmpImm(mnemonic, ops) {
    let rn = parseReg(ops[0]), imm = parseImm(ops[1]), sh = 0;
    if (imm > 0xfff) {
        if ((imm & 0xfff) !== 0) throw new Error(`cmp immediate out of range: ${imm}`);
        sh = 1; imm >>= 12;
    }
    requireRange(imm, 12, false, 'cmp');
    return ((rn.size === 64 ? 1 : 0) << 31) | (1 << 30) | (1 << 29) | 0x11000000 | (sh << 22) | ((imm & 0xfff) << 10) | (rn.num << 5) | 31;
}
function encCmnImm(mnemonic, ops) {
    let rn = parseReg(ops[0]), imm = parseImm(ops[1]), sh = 0;
    if (imm > 0xfff) {
        if ((imm & 0xfff) !== 0) throw new Error(`cmn immediate out of range: ${imm}`);
        sh = 1; imm >>= 12;
    }
    requireRange(imm, 12, false, 'cmn');
    return ((rn.size === 64 ? 1 : 0) << 31) | (0 << 30) | (1 << 29) | 0x11000000 | (sh << 22) | ((imm & 0xfff) << 10) | (rn.num << 5) | 31;
}
function encNeg(mnemonic, ops) {
    let rd = parseReg(ops[0]), rm = parseReg(ops[1]);
    let s = mnemonic === 'negs' ? 1 : 0;
    let shift = 0, imm6 = 0;
    if (ops[2]) {

        let m = ops[2].match(/^(lsl|lsr|asr)\s+#?(\d+)$/);
        if (!m) throw new Error(`Bad shift: ${ops[2]}`);
        shift = { lsl: 0, lsr: 1, asr: 2 }[m[1]];
        imm6 = parseInt(m[2], 10);
        requireRange(imm6, rd.size === 64 ? 6 : 5, false, mnemonic);
    }
    return ((rd.size === 64 ? 1 : 0) << 31) | (1 << 30) | (s << 29) | 0x0b000000 | (shift << 22) | (rm.num << 16) | (imm6 << 10) | (31 << 5) | rd.num;
}
function encAdvSimd2RegMisc(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]);
    let arrangement = rd.arrangement;
    let Q = /^(16b|8h|4s|2d)$/.test(arrangement) ? 1 : 0;

    if (mnemonic === 'rev64' || mnemonic === 'rev32') {
        const sizeMap = { '8b': 0, '16b': 0, '4h': 1, '8h': 1, '2s': 2, '4s': 2 };
        let size = sizeMap[arrangement];
        if (size === undefined) throw new Error(`Bad arrangement for ${mnemonic}: ${arrangement}`);
        let U = mnemonic === 'rev32' ? 1 : 0;
        return 0x0e200800 | (Q << 30) | (U << 29) | (size << 22) | (0b00000 << 12) | (rn.num << 5) | rd.num;
    }
    if (mnemonic === 'rev16') {
        return 0x0e200800 | (Q << 30) | (0b00001 << 12) | (rn.num << 5) | rd.num;
    }
    if (mnemonic === 'cls' || mnemonic === 'clz') {
        const sizeMap = { '8b': 0, '16b': 0, '4h': 1, '8h': 1, '2s': 2, '4s': 2 };
        let size = sizeMap[arrangement];
        if (size === undefined) throw new Error(`Bad arrangement for ${mnemonic}: ${arrangement}`);
        let U = mnemonic === 'clz' ? 1 : 0;
        return 0x0e200800 | (Q << 30) | (U << 29) | (size << 22) | (0b00100 << 12) | (rn.num << 5) | rd.num;
    }
    if (mnemonic === 'cnt' || mnemonic === 'not') {
        if (!/^(8b|16b)$/.test(arrangement)) throw new Error(`Bad arrangement for ${mnemonic}: ${arrangement}`);
        let U = mnemonic === 'not' ? 1 : 0;
        return 0x0e200800 | (Q << 30) | (U << 29) | (0b00101 << 12) | (rn.num << 5) | rd.num;
    }
    if (mnemonic === 'abs' || mnemonic === 'neg') {
        const sizeMap = { '8b': 0, '16b': 0, '4h': 1, '8h': 1, '2s': 2, '4s': 2, '2d': 3 };
        let size = sizeMap[arrangement];
        if (size === undefined) throw new Error(`Bad arrangement for ${mnemonic}: ${arrangement}`);
        let U = mnemonic === 'neg' ? 1 : 0;
        return 0x0e200800 | (Q << 30) | (U << 29) | (size << 22) | (0b01011 << 12) | (rn.num << 5) | rd.num;
    }
    if (['cmeq', 'cmgt', 'cmge', 'cmle', 'cmlt'].includes(mnemonic) && ops[2] && ops[2].replace('#', '') === '0') {
        const sizeMap = { '8b': 0, '16b': 0, '4h': 1, '8h': 1, '2s': 2, '4s': 2, '2d': 3 };
        let size = sizeMap[arrangement];
        if (size === undefined) throw new Error(`Bad arrangement for ${mnemonic}: ${arrangement}`);
        const table = { cmgt: [0b01000, 0], cmge: [0b01000, 1], cmeq: [0b01001, 0], cmle: [0b01001, 1], cmlt: [0b01010, 0] };
        let [opcode, U] = table[mnemonic];
        return 0x0e200800 | (Q << 30) | (U << 29) | (size << 22) | (opcode << 12) | (rn.num << 5) | rd.num;
    }
    if (mnemonic === 'fabs' || mnemonic === 'fneg' || mnemonic === 'fsqrt') {
        if (!/^(2s|4s|2d)$/.test(arrangement)) throw new Error(`Bad arrangement for ${mnemonic}: ${arrangement}`);
        let sz = (arrangement === '2d' ? 1 : 0) | 0b10;
        if (mnemonic === 'fsqrt') return 0x0e200800 | (Q << 30) | (1 << 29) | (sz << 22) | (0b11111 << 12) | (rn.num << 5) | rd.num;
        let U = mnemonic === 'fneg' ? 1 : 0;
        return 0x0e200800 | (Q << 30) | (U << 29) | (sz << 22) | (0b01111 << 12) | (rn.num << 5) | rd.num;
    }
    if (['fcmeq', 'fcmgt', 'fcmge', 'fcmle', 'fcmlt'].includes(mnemonic) && ops[2] && parseFloat(ops[2].replace('#', '')) === 0) {
        if (!/^(2s|4s|2d)$/.test(arrangement)) throw new Error(`Bad arrangement for ${mnemonic}: ${arrangement}`);
        let sz = (arrangement === '2d' ? 1 : 0) | 0b10;
        const table = { fcmgt: [0b01100, 0], fcmge: [0b01100, 1], fcmeq: [0b01101, 0], fcmle: [0b01101, 1], fcmlt: [0b01110, 0] };
        let [opcode, U] = table[mnemonic];
        return 0x0e200800 | (Q << 30) | (U << 29) | (sz << 22) | (opcode << 12) | (rn.num << 5) | rd.num;
    }
    if (mnemonic.startsWith('frint')) {
        if (!/^(2s|4s|2d)$/.test(arrangement)) throw new Error(`Bad arrangement for ${mnemonic}: ${arrangement}`);
        const table = {
            frintn: [0b11000, 0, 0], frintp: [0b11000, 0, 1], frinta: [0b11000, 1, 0],
            frintm: [0b11001, 0, 0], frintz: [0b11001, 0, 1], frintx: [0b11001, 1, 0], frinti: [0b11001, 1, 1],
        };
        let inf = table[mnemonic];
        if (!inf) throw new Error(`Unsupported instruction: ${mnemonic}`);
        let [opcode, U, a] = inf;
        let size = (a << 1) | (arrangement === '2d' ? 1 : 0);
        return 0x0e200800 | (Q << 30) | (U << 29) | (size << 22) | (opcode << 12) | (rn.num << 5) | rd.num;
    }
    throw new Error(`Unsupported instruction: ${mnemonic}`);
}
function encAdvSimd3Different(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]), rm = parseSimdReg(ops[2]);
    let m = mnemonic.match(/^([a-z]+?)(2)?$/);
    let base = m[1], isQ2 = m[2] === '2';
    const sizeFromArr = { '8b': 0, '16b': 0, '4h': 1, '8h': 1, '2s': 2, '4s': 2 };

    const longOps = { saddl: [0, 0], uaddl: [0, 1], ssubl: [2, 0], usubl: [2, 1], sabal: [5, 0], uabal: [5, 1],
        sabdl: [7, 0], uabdl: [7, 1], smlal: [8, 0], umlal: [8, 1], smlsl: [10, 0], umlsl: [10, 1],
        smull: [12, 0], umull: [12, 1] };
    const wideOps = { saddw: [1, 0], uaddw: [1, 1], ssubw: [3, 0], usubw: [3, 1] };
    const narrowOps = { addhn: [4, 0], raddhn: [4, 1], subhn: [6, 0], rsubhn: [6, 1] };

    if (base in longOps) {
        let [opcode, U] = longOps[base];
        let size = sizeFromArr[rn.arrangement];
        let Q = isQ2 ? 1 : 0;
        return 0x0e200000 | (Q << 30) | (U << 29) | (size << 22) | (rm.num << 16) | (opcode << 12) | (rn.num << 5) | rd.num;
    }
    if (base in wideOps) {
        let [opcode, U] = wideOps[base];
        let size = sizeFromArr[rm.arrangement];
        let Q = isQ2 ? 1 : 0;
        return 0x0e200000 | (Q << 30) | (U << 29) | (size << 22) | (rm.num << 16) | (opcode << 12) | (rn.num << 5) | rd.num;
    }
    if (base in narrowOps) {
        let [opcode, U] = narrowOps[base];
        const sizeFromWideArr = { '8h': 0, '4s': 1, '2d': 2 };
        let size = sizeFromWideArr[rn.arrangement];
        let Q = isQ2 ? 1 : 0;
        return 0x0e200000 | (Q << 30) | (U << 29) | (size << 22) | (rm.num << 16) | (opcode << 12) | (rn.num << 5) | rd.num;
    }
    if (base === 'pmull') {
        const srcQ = { '8b': 0, '16b': 1, '1d': 0, '2d': 1 };
        const sizeFromPmull = { '8b': 0, '16b': 0, '1d': 3, '2d': 3 };
        const dstFromSize = { 0: '8h', 3: '1q' };
        let size = sizeFromPmull[rn.arrangement];
        let Q = isQ2 ? 1 : 0;
        if (size === undefined || rm.arrangement !== rn.arrangement || Q !== srcQ[rn.arrangement] ||
            rd.arrangement !== dstFromSize[size]) {
            throw new Error(`Bad arrangement for ${mnemonic}: ${ops.join(', ')}`);
        }
        return 0x0e200000 | (Q << 30) | (size << 22) | (rm.num << 16) | (0b1110 << 12) | (rn.num << 5) | rd.num;
    }
    throw new Error(`Unsupported instruction: ${mnemonic}`);
}
function parseSimdIndexedReg(s) {
    let m = String(s).toLowerCase().trim().match(/^v(\d+)\.([bhsd])\[(\d+)\]$/);
    if (!m) throw new Error(`Bad indexed SIMD operand: ${s}`);
    return { num: parseInt(m[1], 10), elemSize: m[2], index: parseInt(m[3], 10) };
}
function encAdvSimdVectorByElement(mnemonic, ops) {

    if (/^[hs]\d+$/i.test(ops[0])) {
        let rd = { num: parseInt(ops[0].slice(1), 10) };
        let rn = { num: parseInt(ops[1].slice(1), 10) };
        let rmIdx = parseSimdIndexedReg(ops[2]);
        const opcMapScalar = { sqdmulh: [0b1100, 0], sqrdmulh: [0b1101, 0] };
        let inf = opcMapScalar[mnemonic];
        if (!inf) throw new Error(`Unsupported scalar-by-element instruction: ${mnemonic}`);
        let [opcode, U] = inf;
        let size, H, L, M, rmLow;
        if (rmIdx.elemSize === 'h') {
            size = 1;
            let index = rmIdx.index;
            H = (index >> 2) & 1; L = (index >> 1) & 1; M = index & 1;
            rmLow = rmIdx.num & 0xf;
        } else {
            size = 2;
            let index = rmIdx.index;
            H = (index >> 1) & 1; L = index & 1; M = (rmIdx.num >> 4) & 1;
            rmLow = rmIdx.num & 0xf;
        }
        return ((1 << 30) | (U << 29) | (0b11111 << 24) | (size << 22) | (L << 21) | (M << 20) |
            (rmLow << 16) | (opcode << 12) | (H << 11) | (rn.num << 5) | rd.num) >>> 0;
    }
    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]);
    let rmIdx = parseSimdIndexedReg(ops[2]);
    let isLongOp = /^(smull|umull|smlal|umlal|smlsl|umlsl|sqdmull)2?$/.test(mnemonic);
    let arrangement = isLongOp ? rn.arrangement : rd.arrangement;
    let Q = /^(8h|4s|2d)$/.test(arrangement) ? 1 : 0;

    if (elemSizeFieldOf(rmIdx.elemSize) === 1) {
        let index = rmIdx.index;
        let H = (index >> 2) & 1, L = (index >> 1) & 1, M = index & 1;
        let rmLow = rmIdx.num & 0xf;
        return buildVecElem(1, Q, H, L, M, rmLow);
    }
    let index = rmIdx.index;
    let H = rmIdx.elemSize === 'd' ? index : (index >> 1) & 1;
    let L = rmIdx.elemSize === 'd' ? 0 : index & 1;
    let M = (rmIdx.num >> 4) & 1;
    let rmLow = rmIdx.num & 0xf;
    let size = rmIdx.elemSize === 'd' ? 3 : 2;
    return buildVecElem(size, Q, H, L, M, rmLow);

    function elemSizeFieldOf(c) { return { b: 0, h: 1, s: 2, d: 3 }[c]; }

    function buildVecElem(size, Q, H, L, M, rmLow) {
        const opcTable = {
            mul: [0b1000, 0], mla: [0b0000, 1], mls: [0b0100, 1],
            fmul: [0b1001, 0], fmla: [0b0001, 0], fmls: [0b0101, 0],
            smull: [0b1010, 0], umull: [0b1010, 1], smull2: [0b1010, 0], umull2: [0b1010, 1],
            smlal: [0b0010, 0], umlal: [0b0010, 1], smlal2: [0b0010, 0], umlal2: [0b0010, 1],
            smlsl: [0b0110, 0], umlsl: [0b0110, 1], smlsl2: [0b0110, 0], umlsl2: [0b0110, 1],
            sqdmull: [0b1011, 0], sqdmull2: [0b1011, 0],
            sqdmulh: [0b1100, 0], sqrdmulh: [0b1101, 0],
        };
        let inf = opcTable[mnemonic];
        if (!inf) throw new Error(`Unsupported instruction: ${mnemonic}`);
        let [opcode, U] = inf;
        return 0x0f000000 | (Q << 30) | (U << 29) | (size << 22) | (L << 21) | (M << 20) |
            (rmLow << 16) | (opcode << 12) | (H << 11) | (rn.num << 5) | rd.num;
    }
}

function encCbz(mnemonic, ops) {
    let rt = parseReg(ops[0]);
    let imm = parseImm(ops[1]);
    requireAligned(imm, 4, mnemonic);
    let off = imm >> 2;
    requireRange(off, 19, true, mnemonic);
    return ((rt.size === 64 ? 1 : 0) << 31) | (mnemonic === 'cbnz' ? 1 << 24 : 0) | 0x34000000 | ((off & 0x7ffff) << 5) | rt.num;
}
function encTbz(mnemonic, ops) {
    let rt = parseReg(ops[0]), bit = parseImm(ops[1]);
    requireRange(bit, rt.size === 64 ? 6 : 5, false, mnemonic);
    let immOff = parseImm(ops[2]);
    requireAligned(immOff, 4, mnemonic);
    let off = immOff >> 2;
    requireRange(off, 14, true, mnemonic);
    return ((bit & 0x20) << 26) | (mnemonic === 'tbnz' ? 1 << 24 : 0) | 0x36000000 |
        ((bit & 0x1f) << 19) | ((off & 0x3fff) << 5) | rt.num;
}
function encLdrLiteral(mnemonic, ops) {
    if (mnemonic === 'ldrsw') {
        let rt = parseReg(ops[0]);
        let off = parseImm(ops[1]) >> 2;
        return 0x98000000 | ((off & 0x7ffff) << 5) | rt.num;
    }
    let rt0 = ops[0].toLowerCase();
    let isSimdLit = /^[sdq]\d+$/.test(rt0);
    let off = parseImm(ops[1]) >> 2;
    if (isSimdLit) {
        let p = rt0[0], num = parseInt(rt0.slice(1), 10);
        let opc = p === 's' ? 0 : p === 'd' ? 1 : 2;
        return 0x1c000000 | (opc << 30) | ((off & 0x7ffff) << 5) | num;
    }
    let rt = parseReg(ops[0]);
    return (rt.size === 64 ? 0x58000000 : 0x18000000) | ((off & 0x7ffff) << 5) | rt.num;
}
function encPrfm(mnemonic, ops) {
    let hintStr = ops[0].toLowerCase();
    let rt;
    const named = {
        pldl1keep: 0, pldl1strm: 1, pldl2keep: 2, pldl2strm: 3, pldl3keep: 4, pldl3strm: 5,
        plil1keep: 8, plil1strm: 9, plil2keep: 10, plil2strm: 11, plil3keep: 12, plil3strm: 13,
        pstl1keep: 16, pstl1strm: 17, pstl2keep: 18, pstl2strm: 19, pstl3keep: 20, pstl3strm: 21,
    };
    if (hintStr in named) rt = named[hintStr];
    else if (hintStr.startsWith('#')) rt = parseImm(hintStr);
    else throw new Error(`Unknown prfm hint: ${ops[0]}`);
    let memOp = ops.slice(1).join(', ');
    let m = memOp.match(/^\[(sp|x\d+)(?:,\s*#?([+-]?(?:0x[0-9a-f]+|\d+)))?\]$/);
    if (!m) throw new Error(`Unsupported address mode for prfm: ${memOp}`);
    let rn = m[1] === 'sp' ? 31 : parseInt(m[1].replace(/^x/, ''), 10);
    let offset = parseImm(m[2] || '0');
    requireAligned(offset, 8, 'prfm');
    let imm12 = offset >> 3;
    requireRange(imm12, 12, false, 'prfm');
    return (3 << 30) | 0x39000000 | (2 << 22) | (imm12 << 10) | (rn << 5) | rt;
}
function encLoadStore(mnemonic, ops) {
    let rtOp = ops[0].toLowerCase();
    let isSimd = /^[bhsdq]\d+$/.test(rtOp) && !['ldrb', 'strb', 'ldrsb', 'ldursb'].includes(mnemonic);
    let rt, simdPrefix, simdNum;
    if (isSimd) {
        simdPrefix = rtOp[0]; simdNum = parseInt(rtOp.slice(1), 10);
    } else {
        rt = parseReg(ops[0]);
    }
    let memText = ops[1] + (ops[2] ? `, ${ops[2]}` : '');
    let regOffMatch = memText.match(/^\[(sp|[xw]\d+)\s*,\s*([xw]\d+|wzr|xzr)(?:\s*,\s*(lsl|uxtw|sxtw|sxtx)\s*(?:#(\d+))?)?\]$/i);
    let pre = memText.match(/^\[(sp|[xw]\d+)(?:,\s*#?([+-]?(?:0x[0-9a-f]+|\d+)))?\]!$/);
    let post = memText.match(/^\[(sp|[xw]\d+)\],\s*#?([+-]?(?:0x[0-9a-f]+|\d+))$/);
    let unsigned = memText.match(/^\[(sp|[xw]\d+)(?:,\s*#?([+-]?(?:0x[0-9a-f]+|\d+)))?\]$/);

    let isSignedLoad = ['ldrsb', 'ldursb', 'ldrsh', 'ldursh', 'ldrsw', 'ldursw'].includes(mnemonic);
    let isUnscaledExplicit = mnemonic.startsWith('ldur') || mnemonic.startsWith('stur');
    let baseName = isUnscaledExplicit ? mnemonic.replace('ur', 'r') : mnemonic;

    let size;
    if (isSimd) size = { b: 0, h: 1, s: 2, d: 3, q: 0 }[simdPrefix];
    else size = baseName.endsWith('b') ? 0 : baseName.endsWith('h') ? 1 : (isSignedLoad && baseName === 'ldrsw') ? 2 : (rt.size === 64 ? 3 : 2);
    let load = baseName.startsWith('ldr');

    if (regOffMatch) {
        let rnText = regOffMatch[1], rmText = regOffMatch[2].toLowerCase();
        let extType = (regOffMatch[3] || 'lsl').toLowerCase();
        let shiftPresent = regOffMatch[4] !== undefined || (memText.match(/,\s*(lsl|uxtw|sxtw|sxtx)\s*$/i) !== null);
        let shiftAmt = regOffMatch[4] ? parseInt(regOffMatch[4], 10) : 0;
        let rn = rnText === 'sp' ? 31 : parseReg(rnText).num;
        let rmNum = /^[xw]zr$/.test(rmText) ? 31 : parseReg(rmText).num;
        const optMap = { uxtw: 2, lsl: 3, sxtw: 6, sxtx: 7 };
        let option = optMap[extType];
        let s = shiftPresent ? 1 : 0;
        if (isSimd) {
            let opc2 = simdPrefix === 'q' ? (load ? 3 : 2) : (load ? 1 : 0);
            let sizeField = simdPrefix === 'q' ? 0 : size;
            return (sizeField << 30) | 0x3c200800 | (opc2 << 22) | (rmNum << 16) | (option << 13) | (s << 12) | (1 << 11) | (rn << 5) | simdNum;
        }
        let opc = isSignedLoad ? (baseName === 'ldrsw' ? 2 : (rt.size === 64 ? 2 : 3)) : (load ? 1 : 0);
        return (size << 30) | 0x38200800 | (opc << 22) | (rmNum << 16) | (option << 13) | (s << 12) | (1 << 11) | (rn << 5) | rt.num;
    }

    let rnText, offset, mode;
    if (post) { mode = 1; rnText = post[1]; offset = parseImm(post[2]); }
    else if (pre) { mode = 3; rnText = pre[1]; offset = parseImm(pre[2] || '0'); }
    else if (unsigned) { mode = isUnscaledExplicit ? 0 : 2; rnText = unsigned[1]; offset = parseImm(unsigned[2] || '0'); }
    else throw new Error(`Unsupported address mode: ${memText}`);

    let rn = rnText === 'sp' ? 31 : parseReg(rnText).num;

    if (isSimd) {
        let effSize = simdPrefix === 'q' ? 4 : size;
        if (mode === 2 && offset >= 0 && (offset & ((1 << effSize) - 1)) === 0) {
            let imm12 = offset >> effSize;
            requireRange(imm12, 12, false, mnemonic);
            let opc = simdPrefix === 'q' ? (load ? 3 : 2) : (load ? 1 : 0);
            return (size << 30) | 0x3d000000 | (opc << 22) | (imm12 << 10) | (rn << 5) | simdNum;
        }
        requireRange(offset, 9, true, mnemonic);
        let opc = simdPrefix === 'q' ? (load ? 3 : 2) : (load ? 1 : 0);
        return (size << 30) | 0x3c000000 | (opc << 22) | ((offset & 0x1ff) << 12) | (mode << 10) | (rn << 5) | simdNum;
    }
    if (isSignedLoad) {
        let opc = baseName === 'ldrsw' ? 2 : (rt.size === 64 ? 2 : 3);
        if (mode === 2 && offset >= 0 && (offset & ((1 << size) - 1)) === 0) {
            let imm12 = offset >> size;
            requireRange(imm12, 12, false, mnemonic);
            return (size << 30) | 0x39000000 | (opc << 22) | (imm12 << 10) | (rn << 5) | rt.num;
        }
        requireRange(offset, 9, true, mnemonic);
        return (size << 30) | 0x38000000 | (opc << 22) | ((offset & 0x1ff) << 12) | (mode << 10) | (rn << 5) | rt.num;
    }
    if (mode === 2 && offset >= 0 && (offset & ((1 << size) - 1)) === 0) {
        let imm12 = offset >> size;
        requireRange(imm12, 12, false, mnemonic);
        return (size << 30) | 0x39000000 | (load ? 1 << 22 : 0) | (imm12 << 10) | (rn << 5) | rt.num;
    }
    requireRange(offset, 9, true, mnemonic);
    return (size << 30) | 0x38000000 | (load ? 1 << 22 : 0) | ((offset & 0x1ff) << 12) |
        (mode << 10) | (rn << 5) | rt.num;
}
function encFpArith(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]), rm = parseSimdReg(ops[2]);
    const opcodeMap = { fmul: 0, fdiv: 1, fadd: 2, fsub: 3, fmax: 4, fmin: 5, fmaxnm: 6, fminnm: 7, fnmul: 8 };
    let type = rd.prefix === 'd' ? 1 : rd.prefix === 'h' ? 3 : 0;
    return 0x1e200800 | (type << 22) | (rm.num << 16) | (opcodeMap[mnemonic] << 12) | (rn.num << 5) | rd.num;
}
function encFcmp(mnemonic, ops) {
    let rn = parseSimdReg(ops[0]);
    let type = rn.prefix === 'd' ? 1 : rn.prefix === 'h' ? 3 : 0;
    let e = mnemonic === 'fcmpe' ? 1 : 0;
    if (ops[1] === '#0.0' || ops[1] === '#0') {
        return 0x1e202008 | (type << 22) | (e << 4) | (rn.num << 5);
    }
    let rm = parseSimdReg(ops[1]);
    return 0x1e202000 | (type << 22) | (rm.num << 16) | (e << 4) | (rn.num << 5);
}
function encFccmp(mnemonic, ops) {
    let rn = parseSimdReg(ops[0]), rm = parseSimdReg(ops[1]);
    let nzcv = parseImm(ops[2]);
    let cond = condNames.indexOf(ops[3]);
    if (cond < 0) throw new Error(`Bad condition: ${ops[3]}`);
    let type = rn.prefix === 'd' ? 1 : rn.prefix === 'h' ? 3 : 0;
    let op = mnemonic === 'fccmpe' ? 1 : 0;
    return 0x1e200400 | (type << 22) | (rm.num << 16) | (cond << 12) | (rn.num << 5) | (op << 4) | nzcv;
}
function encFcsel(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]), rm = parseSimdReg(ops[2]);
    let cond = condNames.indexOf(ops[3]);
    if (cond < 0) throw new Error(`Bad condition: ${ops[3]}`);
    let type = rd.prefix === 'd' ? 1 : rd.prefix === 'h' ? 3 : 0;
    return 0x1e200c00 | (type << 22) | (rm.num << 16) | (cond << 12) | (rn.num << 5) | rd.num;
}
function encFp1Source(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]);
    const opcodeMap = { fabs: 1, fneg: 2, fsqrt: 3, frintn: 8, frintp: 9, frintm: 10, frintz: 11, frinta: 12, frintx: 14, frinti: 15 };
    let type = rd.prefix === 'd' ? 1 : rd.prefix === 'h' ? 3 : 0;
    return 0x1e204000 | (type << 22) | (opcodeMap[mnemonic] << 15) | (rn.num << 5) | rd.num;
}
function encFcvt(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]);
    let srcType = rn.prefix === 'd' ? 1 : rn.prefix === 'h' ? 3 : 0;
    const dstOpc = { s: 4, d: 5, h: 7 };
    let opcode = dstOpc[rd.prefix];
    if (opcode === undefined) throw new Error(`Bad fcvt destination: ${ops[0]}`);
    return 0x1e204000 | (srcType << 22) | (opcode << 15) | (rn.num << 5) | rd.num;
}
function encScvtfUcvtf(mnemonic, ops) {
    if (/^v\d+\./i.test(ops[0] || '')) {
        let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]);
        const sizeMap = { '2s': 0, '4s': 0, '2d': 1 };
        let size = sizeMap[rd.arrangement];
        if (size === undefined) throw new Error(`Bad arrangement for ${mnemonic}: ${rd.arrangement}`);
        if (rd.arrangement !== rn.arrangement) throw new Error(`Bad arrangement for ${mnemonic}: ${ops[1]}`);
        let Q = QfromArr(rd.arrangement);
        let U = mnemonic === 'ucvtf' ? 1 : 0;
        return 0x0e21d800 | (Q << 30) | (U << 29) | (size << 22) | (rn.num << 5) | rd.num;
    }
    if (!/^[bhsdq]\d+$/i.test(ops[1] || '')) {
        let rd = parseSimdReg(ops[0]), rn = parseReg(ops[1]);
        let type = rd.prefix === 'd' ? 1 : rd.prefix === 'h' ? 3 : 0;
        if (ops[2] && ops[2].startsWith('#')) {
            let fbits = parseImm(ops[2]);
            let scale = 64 - fbits;
            requireRange(scale, 6, false, mnemonic);
            let opcode = mnemonic === 'scvtf' ? 2 : 3;
            return ((rn.size === 64 ? 1 : 0) << 31) | 0x1e000000 | (type << 22) | (opcode << 16) | (scale << 10) | (rn.num << 5) | rd.num;
        }
        let opcode = mnemonic === 'scvtf' ? 2 : 3;
        return ((rn.size === 64 ? 1 : 0) << 31) | 0x1e200000 | (type << 22) | (opcode << 16) | (rn.num << 5) | rd.num;
    }

    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]);
    let U = mnemonic === 'ucvtf' ? 1 : 0;
    let size = rd.prefix === 'd' ? 1 : 0;
    return 0x5e21d800 | (U << 29) | (size << 22) | (rn.num << 5) | rd.num;
}
function encFcvtRound(mnemonic, ops) {
    let rd = parseReg(ops[0]), rn = parseSimdReg(ops[1]);
    let type = rn.prefix === 'd' ? 1 : rn.prefix === 'h' ? 3 : 0;
    if (ops[2] && ops[2].startsWith('#')) {

        let m = mnemonic.match(/^fcvtz([su])$/);
        if (!m) throw new Error(`${mnemonic} does not support a #fbits operand`);
        let fbits = parseImm(ops[2]);
        let scale = 64 - fbits;
        requireRange(scale, 6, false, mnemonic);
        let opcode = m[1] === 's' ? 0 : 1;
        return ((rd.size === 64 ? 1 : 0) << 31) | 0x1e000000 | (type << 22) | (3 << 19) | (opcode << 16) | (scale << 10) | (rn.num << 5) | rd.num;
    }
    const rmodeMap = { n: 0, p: 1, m: 2, z: 3, a: 0 };
    let roundChar = mnemonic[4];
    let unsignedChar = mnemonic[5];
    let rmode = rmodeMap[roundChar];
    let opcode = roundChar === 'a' ? (unsignedChar === 's' ? 4 : 5) : (unsignedChar === 's' ? 0 : 1);
    return ((rd.size === 64 ? 1 : 0) << 31) | 0x1e200000 | (type << 22) | (rmode << 19) | (opcode << 16) | (rn.num << 5) | rd.num;
}
function encFmadd(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]), rm = parseSimdReg(ops[2]), ra = parseSimdReg(ops[3]);
    let type = rd.prefix === 'd' ? 1 : rd.prefix === 'h' ? 3 : 0;
    let o1 = (mnemonic === 'fnmadd' || mnemonic === 'fnmsub') ? 1 : 0;
    let o0 = (mnemonic === 'fmsub' || mnemonic === 'fnmsub') ? 1 : 0;
    return 0x1f000000 | (type << 22) | (o1 << 21) | (rm.num << 16) | (o0 << 15) | (ra.num << 10) | (rn.num << 5) | rd.num;
}
function encFmov(mnemonic, ops, instruction) {
    let d0 = ops[0].toLowerCase();
    if (/^v\d+\.(2s|4s|2d)$/.test(d0) && (ops[1] || '').startsWith('#')) {

        let rdv = parseSimdReg(ops[0]);
        let is2d = rdv.arrangement === '2d';
        let nv = parseFloat(ops[1].replace(/^#/, ''));
        let foundV = null;
        for (let imm8 = 0; imm8 < 256; imm8++) {
            if (fpImm8ToFloat(imm8, is2d) === nv) { foundV = imm8; break; }
        }
        if (foundV === null) throw new Error(`Cannot encode FP immediate: ${ops[1]}`);
        let Qv = /^(4s|2d)$/.test(rdv.arrangement) ? 1 : 0;
        return (0x0f000400 | (Qv << 30) | ((is2d ? 1 : 0) << 29) | (((foundV >> 5) & 7) << 16) | (0b1111 << 12) | ((foundV & 0x1f) << 5) | rdv.num) >>> 0;
    }
    let isSimdDst = /^[bhsdq]\d+$/.test(d0);
    if (isSimdDst && ops[1].startsWith('#')) {
        let rd = parseSimdReg(ops[0]);
        let isDouble = rd.prefix === 'd';
        let n = parseFloat(ops[1].replace(/^#/, ''));
        let found = null;
        for (let imm8 = 0; imm8 < 256; imm8++) {
            if (fpImm8ToFloat(imm8, isDouble) === n) { found = imm8; break; }
        }
        if (found === null) throw new Error(`Cannot encode FP immediate: ${ops[1]}`);
        let type = isDouble ? 1 : 0;
        return 0x1e201000 | (type << 22) | (found << 13) | rd.num;
    }
    if (isSimdDst) {
        let rd = parseSimdReg(ops[0]);
        let src = ops[1].toLowerCase();
        let isSimdSrc = /^[bhsdq]\d+$/.test(src);
        if (isSimdSrc) {
            let rn = parseSimdReg(src);
            let type = rd.prefix === 'd' ? 1 : rd.prefix === 'h' ? 3 : 0;
            return 0x1e204000 | (type << 22) | (rn.num << 5) | rd.num;
        }
        let rn = parseReg(src);
        if (rd.prefix === 's') return 0x1e270000 | (rn.num << 5) | rd.num;
        if (rd.prefix === 'd') return 0x9e670000 | (rn.num << 5) | rd.num;
        throw new Error(`Unsupported fmov form: ${instruction}`);
    }
    if (/\.d\[1\]$/.test(ops[0].toLowerCase())) {
        let rd = parseSimdReg(ops[0].split('.')[0]);
        let rn = parseReg(ops[1]);
        return 0x9eaf0000 | (rn.num << 5) | rd.num;
    }
    if (/\.d\[1\]$/.test((ops[1] || '').toLowerCase())) {
        let rn = parseSimdReg(ops[1].split('.')[0]);
        return 0x9eae0000 | (rn.num << 5) | parseReg(ops[0]).num;
    }
    let rd = parseReg(ops[0]);
    let rn = parseSimdReg(ops[1].toLowerCase());
    if (rn.prefix === 's') return 0x1e260000 | (rn.num << 5) | rd.num;
    if (rn.prefix === 'd') return 0x9e660000 | (rn.num << 5) | rd.num;
    throw new Error(`Unsupported fmov form: ${instruction}`);
}
function parseSimdElem(s) {
    let m = String(s).toLowerCase().trim().match(/^v(\d+)\.([bhsd])\[(\d+)\]$/);
    if (!m) throw new Error(`Bad SIMD element operand: ${s}`);
    return { num: parseInt(m[1], 10), esize: m[2], index: parseInt(m[3], 10) };
}
function imm5FromElem(esize, index) {
    const shift = { b: 1, h: 2, s: 3, d: 4 }[esize];
    const base = { b: 1, h: 2, s: 4, d: 8 }[esize];
    return (index << shift) | base;
}
function encAdvSimdCopy(mnemonic, ops) {
    if (mnemonic === 'mov' && /^[bhsd]\d+$/i.test(ops[0] || '') && /^v\d+\.[bhsd]\[\d+\]$/i.test(ops[1] || '')) {
        mnemonic = 'dup';
    }
    if (mnemonic === 'mov' && /^v\d+\./i.test(ops[1] || '') && /^[xw](\d+)$/.test(ops[0])) {
        let rd = parseReg(ops[0]);
        let src = parseSimdElem(ops[1]);
        const elemBits = { b: 8, h: 16, s: 32, d: 64 }[src.esize];
        if (elemBits > rd.size) throw new Error(`Bad mov operand: ${ops[1]}`);
        mnemonic = elemBits < rd.size ? 'smov' : 'umov';
    }
    if (mnemonic === 'dup') {
        let dst = ops[0].toLowerCase();
        let isScalarDst = /^[bhsd]\d+$/.test(dst);
        let src = parseSimdElem(ops[1]);
        let imm5 = imm5FromElem(src.esize, src.index);
        if (isScalarDst) {
            let Rd = parseInt(dst.slice(1), 10);
            return ((1 << 30) | (0b11110000 << 21) | (1 << 10) | (imm5 << 16) | (src.num << 5) | Rd) >>> 0;
        }
        let rd = parseSimdReg(ops[0]);
        let Q = QfromArr(rd.arrangement);
        if (Q === null) throw new Error(`Bad arrangement: ${rd.arrangement}`);
        return ((Q << 30) | (0b01110000 << 21) | (1 << 10) | (imm5 << 16) | (src.num << 5) | rd.num) >>> 0;
    }
    if (mnemonic === 'ins' || mnemonic === 'mov') {
        let dst = parseSimdElem(ops[0]);
        let imm5 = imm5FromElem(dst.esize, dst.index);
        if (isVectorOperand(ops[1]) === false && /^v\d+\.[bhsd]\[\d+\]$/i.test(ops[1] || '')) {
            let src = parseSimdElem(ops[1]);
            const shift = { b: 0, h: 1, s: 2, d: 3 }[dst.esize];
            let imm4 = src.index << shift;
            return ((1 << 30) | (1 << 29) | (0b01110000 << 21) | (1 << 10) | (imm5 << 16) | (imm4 << 11) | (src.num << 5) | dst.num) >>> 0;
        }
        let rn = parseReg(ops[1]);
        return ((1 << 30) | (0b01110000 << 21) | (0b0011 << 11) | (1 << 10) | (imm5 << 16) | (rn.num << 5) | dst.num) >>> 0;
    }
    if (mnemonic === 'umov' || mnemonic === 'smov') {
        let rd = parseReg(ops[0]);
        let src = parseSimdElem(ops[1]);
        if (mnemonic === 'umov') {
            let ok = src.esize === 'd' ? rd.size === 64 : rd.size === 32;
            if (!ok) throw new Error(`Bad umov operand: ${ops[1]}`);
        } else if (src.esize === 'd' || (src.esize === 's' && rd.size !== 64)) {
            throw new Error(`Bad smov operand: ${ops[1]}`);
        }
        let imm5 = imm5FromElem(src.esize, src.index);
        let Q = rd.size === 64 ? 1 : 0;
        let imm4 = mnemonic === 'umov' ? 0b0111 : 0b0101;
        return ((Q << 30) | (0b01110000 << 21) | (imm4 << 11) | (1 << 10) | (imm5 << 16) | (src.num << 5) | rd.num) >>> 0;
    }
    throw new Error(`Unknown copy-class instruction: ${mnemonic}`);
}
function encDup(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]);
    let rn = parseReg(ops[1]);
    let arrangement = rd.arrangement;
    let Q = /^(16b|8h|4s|2d)$/.test(arrangement) ? 1 : 0;
    let imm5;
    if (/^(8b|16b)$/.test(arrangement)) imm5 = 1;
    else if (/^(4h|8h)$/.test(arrangement)) imm5 = 2;
    else if (/^(2s|4s)$/.test(arrangement)) imm5 = 4;
    else if (arrangement === '2d') imm5 = 8;
    else throw new Error(`Bad arrangement: ${arrangement}`);
    return 0x0e000c00 | (Q << 30) | (imm5 << 16) | (rn.num << 5) | rd.num;
}
function imm8From2dMask(token, src) {
    let v;
    try { v = BigInt(token); } catch (e) { throw new Error(`Bad movi/mvni operand: ${src}`); }
    v = ((v % 0x10000000000000000n) + 0x10000000000000000n) % 0x10000000000000000n;
    let imm8 = 0;
    for (let i = 0; i < 8; i++) {
        let b = (v >> BigInt(8 * i)) & 0xffn;
        if (b === 0xffn) imm8 |= 1 << i;
        else if (b !== 0n) throw new Error(`Bad movi/mvni operand: ${src}`);
    }
    return imm8;
}
function encMovi(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]);
    let arrangement = rd.arrangement;
    if (rd.prefix === 'd' && !arrangement) {

        if (mnemonic !== 'movi') throw new Error(`Bad arrangement for movi/mvni: d`);
        let restD = ops.slice(1).join(', ');
        let md = restD.match(/^#(-?\w+)$/);
        if (!md) throw new Error(`Bad movi/mvni operand: ${restD}`);
        let imm8d = imm8From2dMask(md[1], restD);
        return (0x0f000400 | (1 << 29) | (((imm8d >> 5) & 7) << 16) | (0b1110 << 12) | ((imm8d & 0x1f) << 5) | rd.num) >>> 0;
    }
    let Q = /^(16b|8h|4s|2d)$/.test(arrangement) ? 1 : 0;
    let restOps = ops.slice(1).join(', ');
    let m = restOps.match(/^#(-?\w+)(?:,\s*(lsl|msl)\s*#(\d+))?$/i);
    if (!m) throw new Error(`Bad movi/mvni operand: ${restOps}`);
    let shiftType = (m[2] || '').toLowerCase();
    let shiftAmt = m[3] ? parseInt(m[3], 10) : 0;
    let op = mnemonic === 'mvni' ? 1 : 0;
    let imm8;
    let cmode;
    if (arrangement === '2d') {
        if (op || shiftType || shiftAmt) throw new Error(`Bad arrangement for movi/mvni: ${arrangement}`);
        imm8 = imm8From2dMask(m[1], restOps);
        cmode = 0b1110;
        op = 1;
    } else if (/^(8b|16b)$/.test(arrangement)) {
        if (op) throw new Error(`Bad arrangement for movi/mvni: ${arrangement}`);
        imm8 = parseImm(m[1]) & 0xff;
        cmode = 0b1110;
    } else if (/^(4h|8h)$/.test(arrangement)) {
        imm8 = parseImm(m[1]) & 0xff;
        cmode = shiftAmt === 8 ? 0b1010 : 0b1000;
    } else if (/^(2s|4s)$/.test(arrangement)) {
        imm8 = parseImm(m[1]) & 0xff;
        if (shiftType === 'msl') cmode = shiftAmt === 16 ? 0b1101 : 0b1100;
        else cmode = { 0: 0b0000, 8: 0b0010, 16: 0b0100, 24: 0b0110 }[shiftAmt];
        if (cmode === undefined) throw new Error(`Bad movi/mvni operand: ${restOps}`);
    } else throw new Error(`Bad arrangement for movi/mvni: ${arrangement}`);
    let abc = (imm8 >> 5) & 7, defgh = imm8 & 0x1f;
    return 0x0f000400 | (Q << 30) | (op << 29) | (abc << 16) | (cmode << 12) | (defgh << 5) | rd.num;
}
function encAdvSimdLogicalImm(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]);
    let arrangement = rd.arrangement;
    let restOps = ops.slice(1).join(', ');
    let m = restOps.match(/^#(-?\w+)(?:,\s*(lsl|msl)\s*#(\d+))?$/i);
    if (!m) throw new Error(`Bad ${mnemonic} operand: ${restOps}`);
    if ((m[2] || '').toLowerCase() === 'msl') throw new Error(`Bad ${mnemonic} operand: ${restOps}`);
    let imm8 = parseImm(m[1]) & 0xff;
    let shiftAmt = m[3] ? parseInt(m[3], 10) : 0;
    let op = mnemonic === 'orr' ? 0 : mnemonic === 'bic' ? 1 : null;
    if (op === null) throw new Error(`Unsupported instruction: ${mnemonic}`);
    let cmode;
    if (/^(2s|4s)$/.test(arrangement)) cmode = { 0: 0b0001, 8: 0b0011, 16: 0b0101, 24: 0b0111 }[shiftAmt];
    else if (/^(4h|8h)$/.test(arrangement)) cmode = shiftAmt === 8 ? 0b1011 : 0b1001;
    else throw new Error(`Bad arrangement for ${mnemonic}: ${arrangement}`);
    if (cmode === undefined) throw new Error(`Bad ${mnemonic} operand: ${restOps}`);
    let Q = /^(16b|8h|4s|2d)$/.test(arrangement) ? 1 : 0;
    let abc = (imm8 >> 5) & 7, defgh = imm8 & 0x1f;
    return 0x0f000400 | (Q << 30) | (op << 29) | (abc << 16) | (cmode << 12) | (defgh << 5) | rd.num;
}
function encAdvSimd3Same(mnemonic, ops) {
    if (ops.length >= 2 && (ops[1] || '').startsWith('#')) return encAdvSimdLogicalImm(mnemonic, ops);
    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]), rm = parseSimdReg(ops[2]);
    let arrangement = rd.arrangement;
    let Q = /^(16b|8h|4s|2d)$/.test(arrangement) ? 1 : 0;

    const logicalNames = { and: [0, 0], bic: [0, 1], orr: [0, 2], orn: [0, 3], eor: [1, 0], bsl: [1, 1], bit: [1, 2], bif: [1, 3] };
    if (mnemonic in logicalNames) {
        let [U, size] = logicalNames[mnemonic];
        return 0x0e201c00 | (Q << 30) | (U << 29) | (size << 22) | (rm.num << 16) | (rn.num << 5) | rd.num;
    }

    const intSizeMap = { '8b': 0, '16b': 0, '4h': 1, '8h': 1, '2s': 2, '4s': 2, '2d': 3 };
    const intOps = {
        add: [0, 0b10000], sub: [1, 0b10000],
        mul: [0, 0b10011],
        mla: [0, 0b10010], mls: [1, 0b10010],
        cmtst: [0, 0b10001], cmeq: [1, 0b10001],
        cmgt: [0, 0b00110], cmhi: [1, 0b00110],
        cmge: [0, 0b00111], cmhs: [1, 0b00111],
        smax: [0, 0b01100], umax: [1, 0b01100],
        smin: [0, 0b01101], umin: [1, 0b01101],
        sshl: [0, 0b01000], ushl: [1, 0b01000],
        smaxp: [0, 0b10100], umaxp: [1, 0b10100],
        sminp: [0, 0b10101], uminp: [1, 0b10101],
        addp: [0, 0b10111],
        shadd: [0, 0b00000], uhadd: [1, 0b00000],
        srhadd: [0, 0b00010], urhadd: [1, 0b00010],
        shsub: [0, 0b00100], uhsub: [1, 0b00100],
        sabd: [0, 0b01110], uabd: [1, 0b01110],
        saba: [0, 0b01111], uaba: [1, 0b01111],
    };
    if (mnemonic in intOps) {
        let [U, opcode] = intOps[mnemonic];
        let size = intSizeMap[arrangement];
        if (size === undefined) throw new Error(`Bad arrangement for ${mnemonic}: ${arrangement}`);
        return 0x0e200400 | (Q << 30) | (U << 29) | (size << 22) | (rm.num << 16) | (opcode << 11) | (rn.num << 5) | rd.num;
    }

    const fpOps = {
        fadd: [0, 0, 0b11010], fsub: [0, 1, 0b11010], faddp: [1, 0, 0b11010], fabd: [1, 1, 0b11010],
        fmul: [1, 0, 0b11011],
        fdiv: [1, 0, 0b11111],
        fmax: [0, 0, 0b11110], fmin: [0, 1, 0b11110],
        fmaxnm: [0, 0, 0b11000], fminnm: [0, 1, 0b11000],
        fmla: [0, 0, 0b11001], fmls: [0, 1, 0b11001],
        fcmeq: [0, 0, 0b11100], fcmge: [1, 0, 0b11100], fcmgt: [1, 1, 0b11100],
    };
    if (mnemonic in fpOps) {
        let [U, a, opcode] = fpOps[mnemonic];
        let sz = arrangement === '2d' ? 1 : 0;
        if (!/^(2s|4s|2d)$/.test(arrangement)) throw new Error(`Bad arrangement for ${mnemonic}: ${arrangement}`);
        let size = (a << 1) | sz;
        return 0x0e200400 | (Q << 30) | (U << 29) | (size << 22) | (rm.num << 16) | (opcode << 11) | (rn.num << 5) | rd.num;
    }
    throw new Error(`Unsupported instruction: ${mnemonic}`);
}
function isVectorOperand(op) {
    return /^v\d+\.[0-9a-z]+$/i.test(op || '');
}
function vecOrScalar(scalarFn, vecFn) {
    return (mnemonic, ops, instruction, littleEndian) =>
        isVectorOperand(ops[0]) ? vecFn(mnemonic, ops) : scalarFn(mnemonic, ops, instruction, littleEndian);
}

function parseSimdRegList(s) {

    let inner = s.replace(/^\{/, '').replace(/\}$/, '').trim();
    return inner.split(',').map(r => r.trim());
}

function encLdStMultiple(mnemonic, ops) {

    let regList = parseSimdRegList(ops[0]);
    let count = regList.length;

    let m0 = regList[0].match(/^v(\d+)\.([0-9a-z]+)$/i);
    if (!m0) throw new Error(`Bad SIMD register: ${regList[0]}`);
    let Rt = parseInt(m0[1], 10);
    let arr = m0[2].toLowerCase();

    const arrEnc = {
        '8b': [0, 0], '16b': [0, 1],
        '4h': [1, 0], '8h': [1, 1],
        '2s': [2, 0], '4s': [2, 1],
        '1d': [3, 0], '2d': [3, 1],
    };
    let [size, Q] = arrEnc[arr] || [];
    if (size === undefined) throw new Error(`Unknown arrangement: ${arr}`);

    let L = mnemonic.startsWith('ld') ? 1 : 0;
    const opcMap = {
        'ld1': { 1: 0x7, 2: 0xa, 3: 0x6, 4: 0x2 },
        'st1': { 1: 0x7, 2: 0xa, 3: 0x6, 4: 0x2 },
        'ld2': { 2: 0x8 }, 'st2': { 2: 0x8 },
        'ld3': { 3: 0x4 }, 'st3': { 3: 0x4 },
        'ld4': { 4: 0x0 }, 'st4': { 4: 0x0 },
    };
    let opc = (opcMap[mnemonic] || {})[count];
    if (opc === undefined) throw new Error(`${mnemonic} does not support ${count} registers`);

    let memOp = ops[1];
    let memM = memOp.match(/^\[(sp|x\d+)\]$/);
    if (!memM) throw new Error(`Unsupported address for ${mnemonic}: ${memOp}`);
    let Rn = memM[1] === 'sp' ? 31 : parseInt(memM[1].slice(1), 10);

    let isPost = ops[2] !== undefined;
    let Rm = 0;
    if (isPost) {
        let pi = ops[2];
        if (pi.startsWith('#')) {
            Rm = 31;
        } else {
            Rm = parseInt(pi.replace(/^x/, ''), 10);
        }
    }

    let base = (Q << 30) | (isPost ? 0x0c800000 : 0x0c000000) | (L << 22);
    if (isPost) base |= (Rm << 16);
    base |= (opc << 12) | (size << 10) | (Rn << 5) | Rt;
    return base >>> 0;
}

function encLdNR(mnemonic, ops) {
    const countMap = { ld1r: 1, ld2r: 2, ld3r: 3, ld4r: 4 };
    let count = countMap[mnemonic];
    if (count === undefined) throw new Error(`Unknown mnemonic: ${mnemonic}`);

    let regList = parseSimdRegList(ops[0]);
    if (regList.length !== count) throw new Error(`${mnemonic} expects ${count} register(s)`);

    let m0 = regList[0].match(/^v(\d+)\.([0-9a-z]+)$/i);
    if (!m0) throw new Error(`Bad SIMD register: ${regList[0]}`);
    let Rt = parseInt(m0[1], 10);
    let arr = m0[2].toLowerCase();

    const arrEnc = {
        '8b': [0, 0], '16b': [0, 1],
        '4h': [1, 0], '8h': [1, 1],
        '2s': [2, 0], '4s': [2, 1],
        '1d': [3, 0], '2d': [3, 1],
    };
    let [size, Q] = arrEnc[arr] || [];
    if (size === undefined) throw new Error(`Unknown arrangement: ${arr}`);

    let memM = ops[1].match(/^\[(sp|x\d+)\]$/);
    if (!memM) throw new Error(`Bad address: ${ops[1]}`);
    let Rn = memM[1] === 'sp' ? 31 : parseInt(memM[1].slice(1), 10);

    let isPost = ops[2] !== undefined;
    let Rm = 0;
    if (isPost) {
        let pi = ops[2];
        Rm = pi.startsWith('#') ? 31 : parseInt(pi.replace(/^x/, ''), 10);
    }

    let opcode = (count <= 2) ? 0b110 : 0b111;
    let R      = (count === 2 || count === 4) ? 1 : 0;

    let v = (Q << 30) | 0x0d000000;
    if (isPost) v |= (1 << 23) | (Rm << 16);
    v |= (1 << 22);
    v |= (R << 21);
    v |= (opcode << 13);

    v |= (size << 10);
    v |= (Rn << 5);
    v |= Rt;
    return v >>> 0;
}

function encLdStSingle(mnemonic, ops) {
    let L  = mnemonic.startsWith('ld') ? 1 : 0;
    let n  = parseInt(mnemonic.slice(2), 10);
    if (n < 1 || n > 4) throw new Error(`Unknown mnemonic: ${mnemonic}`);

    let regM = ops[0].match(/^\{([^}]+)\}\[(\d+)\]$/);
    if (!regM) throw new Error(`Bad single-lane operand: ${ops[0]}`);
    let regsStr = regM[1];
    let index   = parseInt(regM[2], 10);
    let regs    = regsStr.split(',').map(s => s.trim());
    if (regs.length !== n) throw new Error(`${mnemonic} expects ${n} register(s), got ${regs.length}`);

    let m0 = regs[0].match(/^v(\d+)\.([bhsd])$/i);
    if (!m0) throw new Error(`Bad single-lane register: ${regs[0]}`);
    let Rt    = parseInt(m0[1], 10);
    let esize = m0[2].toLowerCase();

    let memM = ops[1].match(/^\[(sp|x\d+)\]$/);
    if (!memM) throw new Error(`Bad address: ${ops[1]}`);
    let Rn = memM[1] === 'sp' ? 31 : parseInt(memM[1].slice(1), 10);

    let isPost = ops[2] !== undefined;
    let Rm = 0;
    if (isPost) {
        let pi = ops[2];
        Rm = pi.startsWith('#') ? 31 : parseInt(pi.replace(/^x/, ''), 10);
    }

    let R          = (n === 2 || n === 4) ? 1 : 0;
    let opcodeBit0 = (n === 3 || n === 4) ? 1 : 0;

    let opcodeBase, Q, S, size;
    if (esize === 'b') {
        opcodeBase = 0b000;
        Q    = (index >> 3) & 1;
        S    = (index >> 2) & 1;
        size = index & 3;
    } else if (esize === 'h') {
        if (index > 7) throw new Error(`h index out of range: ${index}`);
        opcodeBase = 0b010;
        Q    = (index >> 2) & 1;
        S    = (index >> 1) & 1;
        size = (index & 1) << 1;
    } else if (esize === 's') {
        if (index > 3) throw new Error(`s index out of range: ${index}`);
        opcodeBase = 0b100;
        Q    = (index >> 1) & 1;
        S    = index & 1;
        size = 0b00;
    } else if (esize === 'd') {
        if (index > 1) throw new Error(`d index out of range: ${index}`);
        opcodeBase = 0b100;
        Q = index & 1;
        S = 0;
        size = 0b01;
    } else {
        throw new Error(`Unknown element size: ${esize}`);
    }

    let opcode = opcodeBase | opcodeBit0;

    let v = (Q << 30) | 0x0d000000;
    if (isPost) v |= (1 << 23) | (Rm << 16);
    v |= (L << 22);
    v |= (R << 21);
    v |= (opcode << 13);
    v |= (S << 12);
    v |= (size << 10);
    v |= (Rn << 5);
    v |= Rt;
    return v >>> 0;
}

function immhImmb(shiftAmt, esize, isRight) {

    let immhb = isRight ? (esize * 2 - shiftAmt) : (esize + shiftAmt);
    return { immh: (immhb >>> 3) & 0xf, immb: immhb & 7 };
}

function esizeFromArr(arr) {
    const m = { '8b': 8, '16b': 8, '4h': 16, '8h': 16, '2s': 32, '4s': 32, '1d': 64, '2d': 64 };
    return m[arr] || null;
}

function QfromArr(arr) {
    const m = { '8b': 0, '16b': 1, '4h': 0, '8h': 1, '2s': 0, '4s': 1, '1d': 0, '2d': 1 };
    return m[arr] !== undefined ? m[arr] : null;
}

function encAdvSimdScalarShiftByImm(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]);
    let shiftAmt = parseImm(ops[2]);
    const shiftInfo = {
        'sshr': { opc: 0x00, U: 0, right: true }, 'ushr': { opc: 0x00, U: 1, right: true },
        'ssra': { opc: 0x02, U: 0, right: true }, 'usra': { opc: 0x02, U: 1, right: true },
        'srshr': { opc: 0x04, U: 0, right: true }, 'urshr': { opc: 0x04, U: 1, right: true },
        'srsra': { opc: 0x06, U: 0, right: true }, 'ursra': { opc: 0x06, U: 1, right: true },
        'sri': { opc: 0x08, U: 1, right: true },
        'shl': { opc: 0x0a, U: 0, right: false }, 'sli': { opc: 0x0a, U: 1, right: false },
        'sqshlu': { opc: 0x0c, U: 1, right: false },
        'sqshl': { opc: 0x0e, U: 0, right: false }, 'uqshl': { opc: 0x0e, U: 1, right: false },
    };
    if (!(mnemonic in shiftInfo)) throw new Error(`Unknown scalar shift-imm instruction: ${mnemonic}`);
    let { opc, U, right } = shiftInfo[mnemonic];
    let { immh, immb } = immhImmb(shiftAmt, 64, right);
    if (immh === 0) throw new Error(`Shift amount out of range: ${shiftAmt}`);
    return ((1 << 30) | (U << 29) | (0b111110 << 23) | (1 << 10) | (immh << 19) | (immb << 16) | (opc << 11) | (rn.num << 5) | rd.num) >>> 0;
}

function encShiftByImm(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]);
    let rn = parseSimdReg(ops[1]);
    let shiftAmt = parseImm(ops[2]);
    let arr = rd.arrangement;
    let esize = esizeFromArr(arr);
    let Q = QfromArr(arr);
    if (esize === null || Q === null) throw new Error(`Bad arrangement: ${arr}`);

    const shiftInfo = {
        'sshr': { opc: 0x00, U: 0, right: true },
        'ushr': { opc: 0x00, U: 1, right: true },
        'ssra': { opc: 0x02, U: 0, right: true },
        'usra': { opc: 0x02, U: 1, right: true },
        'srshr': { opc: 0x04, U: 0, right: true },
        'urshr': { opc: 0x04, U: 1, right: true },
        'srsra': { opc: 0x06, U: 0, right: true },
        'ursra': { opc: 0x06, U: 1, right: true },
        'sri': { opc: 0x08, U: 1, right: true },
        'shl': { opc: 0x0a, U: 0, right: false },
        'sli': { opc: 0x0a, U: 1, right: false },
    };
    if (!(mnemonic in shiftInfo)) throw new Error(`Unknown shift-imm instruction: ${mnemonic}`);
    let { opc, U, right } = shiftInfo[mnemonic];
    let { immh, immb } = immhImmb(shiftAmt, esize, right);
    if (immh === 0) throw new Error(`Shift amount out of range: ${shiftAmt}`);
    return (Q << 30) | (U << 29) | 0x0f000400 | (immh << 19) | (immb << 16) | (opc << 11) | (rn.num << 5) | rd.num;
}

function encSshllUshll(mnemonic, ops) {

    let rd = parseSimdReg(ops[0]);
    let rn = parseSimdReg(ops[1]);
    let isXtl = mnemonic.startsWith('sxtl') || mnemonic.startsWith('uxtl');
    let U = (mnemonic.startsWith('u') || mnemonic.startsWith('ushll')) ? 1 : 0;
    let shiftAmt = isXtl ? 0 : parseImm(ops[2]);

    let srcArr = rn.arrangement;
    let Q2 = mnemonic.endsWith('2') ? 1 : 0;
    let esize = esizeFromArr(srcArr);
    if (!esize) throw new Error(`Bad arrangement: ${srcArr}`);
    let { immh, immb } = immhImmb(shiftAmt, esize, false);
    return (Q2 << 30) | (U << 29) | 0x0f000400 | (immh << 19) | (immb << 16) | (0x14 << 11) | (rn.num << 5) | rd.num;
}

function encShrn(mnemonic, ops) {

    let rd = parseSimdReg(ops[0]);
    let rn = parseSimdReg(ops[1]);
    let shiftAmt = parseImm(ops[2]);
    let Q2 = mnemonic.endsWith('2') ? 1 : 0;
    let isRshrn = mnemonic.startsWith('rshrn');
    let U = 0;
    let opc = isRshrn ? 0x11 : 0x10;

    let srcArr = rn.arrangement;
    let srcEsize = esizeFromArr(srcArr);
    if (!srcEsize) throw new Error(`Bad arrangement: ${srcArr}`);
    let { immh, immb } = immhImmb(shiftAmt, srcEsize / 2, true);

    let immhb2 = srcEsize - shiftAmt;
    immh = (immhb2 >>> 3) & 0xf;
    immb = immhb2 & 7;
    return (Q2 << 30) | (U << 29) | 0x0f000400 | (immh << 19) | (immb << 16) | (opc << 11) | (rn.num << 5) | rd.num;
}

function encPermute(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]);
    let rn = parseSimdReg(ops[1]);
    let rm = parseSimdReg(ops[2]);
    let arr = rd.arrangement;
    const arrEnc = {
        '8b': [0, 0], '16b': [0, 1],
        '4h': [1, 0], '8h': [1, 1],
        '2s': [2, 0], '4s': [2, 1],
        '2d': [3, 1],
    };
    let [size, Q] = arrEnc[arr] || [];
    if (size === undefined) throw new Error(`Bad arrangement: ${arr}`);
    const opcMap = { 'uzp1': 1, 'trn1': 2, 'zip1': 3, 'uzp2': 5, 'trn2': 6, 'zip2': 7 };
    let opc = opcMap[mnemonic];
    if (opc === undefined) throw new Error(`Unknown permute: ${mnemonic}`);

    return (Q << 30) | 0x0e000800 | (size << 22) | (rm.num << 16) | (opc << 12) | (rn.num << 5) | rd.num;
}

function encTblTbx(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]);

    let regList = parseSimdRegList(ops[1]);
    let rm = parseSimdReg(ops[2]);
    let len = regList.length - 1;
    let m0 = regList[0].match(/^v(\d+)/i);
    if (!m0) throw new Error(`Bad table register: ${regList[0]}`);
    let Rn = parseInt(m0[1], 10);
    let arr = rd.arrangement;
    let Q = QfromArr(arr);
    if (Q === null) throw new Error(`Bad arrangement: ${arr}`);
    let op = mnemonic === 'tbx' ? 1 : 0;

    return (Q << 30) | 0x0e000000 | (rm.num << 16) | (len << 13) | (op << 12) | (Rn << 5) | rd.num;
}

function encExt(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]);
    let rn = parseSimdReg(ops[1]);
    let rm = parseSimdReg(ops[2]);
    let index = parseImm(ops[3]);
    let arr = rd.arrangement;
    let Q = QfromArr(arr);
    if (Q === null) throw new Error(`Bad arrangement: ${arr}`);
    if (!Q && index >= 8) throw new Error(`Index out of range for 64-bit EXT: ${index}`);

    return (Q << 30) | 0x2e000000 | (rm.num << 16) | (index << 11) | (rn.num << 5) | rd.num;
}

function encAcrossLanes(mnemonic, ops) {

    let dstReg = ops[0].toLowerCase();
    let srcReg = parseSimdReg(ops[1]);
    let arr = srcReg.arrangement;
    let Rd = parseInt(dstReg.slice(1), 10);
    let Rn = srcReg.num;

    const arrEnc = {
        '8b': [0, 0], '16b': [0, 1],
        '4h': [1, 0], '8h': [1, 1],
        '4s': [2, 1],
    };
    let [size, Q] = arrEnc[arr] || [];
    if (size === undefined) throw new Error(`Bad arrangement for ${mnemonic}: ${arr}`);

    const info = {
        'addv': { U: 0, opc: 0x1b },
        'smaxv': { U: 0, opc: 0x0a },
        'sminv': { U: 0, opc: 0x1a },
        'umaxv': { U: 1, opc: 0x0a },
        'uminv': { U: 1, opc: 0x1a },
        'uaddlv': { U: 1, opc: 0x03 },
        'saddlv': { U: 0, opc: 0x03 },
    };
    let inf = info[mnemonic];
    if (!inf) throw new Error(`Unknown across-lanes instruction: ${mnemonic}`);

    return (Q << 30) | (inf.U << 29) | 0x0e300800 | (size << 22) | (inf.opc << 12) | (Rn << 5) | Rd;
}

function encFpAcrossLanes(mnemonic, ops) {
    let dstReg = ops[0].toLowerCase();
    let srcReg = parseSimdReg(ops[1]);
    let Rd = parseInt(dstReg.slice(1), 10);
    let Rn = srcReg.num;
    if (srcReg.arrangement !== '4s') throw new Error(`${mnemonic} only supports 4s arrangement`);

    const info = {
        'fmaxnmv': { a: 0, opc: 0x0c },
        'fminnmv': { a: 1, opc: 0x0c },
        'fmaxv': { a: 0, opc: 0x0f },
        'fminv': { a: 1, opc: 0x0f },
    };
    let inf = info[mnemonic];
    if (!inf) throw new Error(`Unknown fp-across-lanes: ${mnemonic}`);
    return (1 << 30) | 0x2e300800 | (inf.a << 23) | (inf.opc << 12) | (Rn << 5) | Rd;
}

function encAdvSimdScalar3Same(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]);
    let rn = parseSimdReg(ops[1]);
    let rm = parseSimdReg(ops[2]);

    if (rd.prefix !== 'd') throw new Error(`Scalar SIMD: only d-regs supported`);
    const info = {
        'add': { U: 0, opc: 0b10000 },
        'sub': { U: 1, opc: 0b10000 },
        'cmtst': { U: 0, opc: 0b10001 },
        'cmeq': { U: 1, opc: 0b10001 },
        'cmgt': { U: 0, opc: 0b00110 },
        'cmhi': { U: 1, opc: 0b00110 },
        'cmge': { U: 0, opc: 0b00111 },
        'cmhs': { U: 1, opc: 0b00111 },
        'sshl': { U: 0, opc: 0b01000 },
        'ushl': { U: 1, opc: 0b01000 },
    };
    let inf = info[mnemonic];
    if (!inf) throw new Error(`Unknown scalar 3-same: ${mnemonic}`);

    return (1 << 30) | (inf.U << 29) | 0x5e200400 | (3 << 22) | (rm.num << 16) | (inf.opc << 11) | (rn.num << 5) | rd.num;
}

function encAdvSimdScalarPairwise(mnemonic, ops) {
    let dstReg = ops[0].toLowerCase();
    let Rd = parseInt(dstReg.slice(1), 10);
    let srcReg = parseSimdReg(ops[1]);
    if (srcReg.arrangement !== '2d') throw new Error(`${mnemonic} scalar form requires .2d source`);
    let Rn = srcReg.num;
    const U = 0, size = 3, opc = 0b11011;
    return ((1 << 30) | (U << 29) | (0x1e << 24) | (size << 22) | (0x18 << 17) | (opc << 12) | (2 << 10) | (Rn << 5) | Rd) >>> 0;
}

function encAdvSimdScalar2RegMisc(mnemonic, ops) {
    let rd = parseSimdReg(ops[0]), rn = parseSimdReg(ops[1]);
    const table = {
        cmgt: [0x08, 0], cmge: [0x08, 1], cmeq: [0x09, 0], cmlt: [0x0a, 0], cmle: [0x0a, 1],
        abs: [0x0b, 0], neg: [0x0b, 1],
    };
    let inf = table[mnemonic];
    if (!inf) throw new Error(`Unknown scalar 2-reg-misc: ${mnemonic}`);
    let [opc, U] = inf;
    return (1 << 30) | (U << 29) | 0x5e200800 | (3 << 22) | (opc << 12) | (rn.num << 5) | rd.num;
}

function build2RegMisc(Q, U, size, opcode, Rn, Rd) {
    return ((Q & 1) << 30) | ((U & 1) << 29) | (0b01110 << 24) |
           ((size & 3) << 22) | (0b10000 << 17) | ((opcode & 0x1f) << 12) |
           (0b10 << 10) | ((Rn & 0x1f) << 5) | (Rd & 0x1f);
}

function encNarrowingConvert(mnemonic, ops) {
    const base = mnemonic.replace(/2$/, '');
    const isQ2 = mnemonic.endsWith('2');

    const isScalarDst = /^[bhs]\d+$/.test((ops[0] || '').toLowerCase());
    if (isScalarDst) {
        const dstM = ops[0].match(/^([bhs])(\d+)$/i);
        const srcM = ops[1].match(/^([hsd])(\d+)$/i);
        if (!dstM || !srcM) throw new Error(`Bad scalar operands: ${ops}`);
        const Rd = parseInt(dstM[2]);
        const Rn = parseInt(srcM[2]);

        let opcode, U, size;
        if (base === 'fcvtxn') {
            opcode = 0x16; U = 1; size = 1;
        } else {
            const sizeMap = { b: 0, h: 1, s: 2 };
            size = sizeMap[dstM[1].toLowerCase()];
            if (base === 'sqxtn')  { opcode = 0x14; U = 0; }
            else if (base === 'uqxtn')  { opcode = 0x14; U = 1; }
            else if (base === 'sqxtun') { opcode = 0x12; U = 1; }
            else throw new Error(`Unsupported scalar narrowing: ${mnemonic}`);
        }
        return ((1 << 30) | (U << 29) | (0b11110 << 24) | (size << 22) |
                (0b10000 << 17) | (opcode << 12) | (0b10 << 10) |
                (Rn << 5) | Rd) >>> 0;
    }

    const m0 = ops[0].match(/^v(\d+)\.([0-9a-z]+)$/i);
    if (!m0) throw new Error(`Bad operand: ${ops[0]}`);
    const Rd = parseInt(m0[1]);
    const dstArr = m0[2].toLowerCase();
    const m1 = ops[1].match(/^v(\d+)\.([0-9a-z]+)$/i);
    if (!m1) throw new Error(`Bad operand: ${ops[1]}`);
    const Rn = parseInt(m1[1]);

    let Q, U, size, opcode;
    if (base === 'xtn') {
        U = 0; opcode = 0x12;
        const sizeMap = { '8b': 0, '4h': 1, '2s': 2, '16b': 0, '8h': 1, '4s': 2 };
        size = sizeMap[dstArr]; Q = isQ2 ? 1 : 0;
    } else if (base === 'sqxtun') {
        U = 1; opcode = 0x12;
        const sizeMap = { '8b': 0, '4h': 1, '2s': 2, '16b': 0, '8h': 1, '4s': 2 };
        size = sizeMap[dstArr]; Q = isQ2 ? 1 : 0;
    } else if (base === 'sqxtn') {
        U = 0; opcode = 0x14;
        const sizeMap = { '8b': 0, '4h': 1, '2s': 2, '16b': 0, '8h': 1, '4s': 2 };
        size = sizeMap[dstArr]; Q = isQ2 ? 1 : 0;
    } else if (base === 'uqxtn') {
        U = 1; opcode = 0x14;
        const sizeMap = { '8b': 0, '4h': 1, '2s': 2, '16b': 0, '8h': 1, '4s': 2 };
        size = sizeMap[dstArr]; Q = isQ2 ? 1 : 0;
    } else if (base === 'fcvtn') {
        U = 0; opcode = 0x16;
        const sizeMap = { '4h': 0, '2s': 1, '8h': 0, '4s': 1 };
        size = sizeMap[dstArr]; Q = isQ2 ? 1 : 0;
    } else if (base === 'fcvtl') {
        U = 0; opcode = 0x17;
        const sizeMap = { '4s': 0, '2d': 1 };
        size = sizeMap[dstArr]; Q = isQ2 ? 1 : 0;
    } else if (base === 'fcvtxn') {
        U = 1; opcode = 0x16;
        const sizeMap = { '2s': 1, '4s': 1 };
        size = sizeMap[dstArr]; Q = isQ2 ? 1 : 0;
    } else {
        throw new Error(`Unknown narrowing mnemonic: ${mnemonic}`);
    }
    if (size === undefined) throw new Error(`${mnemonic} bad arrangement: ${dstArr}`);
    return build2RegMisc(Q, U, size, opcode, Rn, Rd) >>> 0;
}

function encSaturating3Same(mnemonic, ops) {
    const opcMap = {
        sqadd: [0x01, 0], uqadd: [0x01, 1],
        sqsub: [0x05, 0], uqsub: [0x05, 1],
        sqshl: [0x09, 0], uqshl: [0x09, 1],
        sqdmulh: [0x16, 0], sqrdmulh: [0x16, 1],
    };
    const inf = opcMap[mnemonic];
    if (!inf) throw new Error(`Unknown saturating op: ${mnemonic}`);
    const [opc, U] = inf;

    const isScalar = /^[bhsd]\d+$/.test((ops[0] || '').toLowerCase());
    if (isScalar) {
        const sizeMap = { b: 0, h: 1, s: 2, d: 3 };
        const mRd = ops[0].match(/^([bhsd])(\d+)$/i);
        const mRn = ops[1].match(/^([bhsd])(\d+)$/i);
        const mRm = ops[2].match(/^([bhsd])(\d+)$/i);
        if (!mRd || !mRn || !mRm) throw new Error(`Bad scalar operands`);
        const size = sizeMap[mRd[1].toLowerCase()];
        const Rd = parseInt(mRd[2]), Rn = parseInt(mRn[2]), Rm = parseInt(mRm[2]);

        return ((1<<30)|(U<<29)|(0b11110<<24)|(size<<22)|(1<<21)|
                (Rm<<16)|(opc<<11)|(1<<10)|(Rn<<5)|Rd) >>> 0;
    }

    const m0 = ops[0].match(/^v(\d+)\.([0-9a-z]+)$/i);
    const m1 = ops[1].match(/^v(\d+)\.([0-9a-z]+)$/i);
    const m2 = ops[2].match(/^v(\d+)\.([0-9a-z]+)$/i);
    if (!m0 || !m1 || !m2) throw new Error(`Bad vector operands`);
    const arrEnc = { '8b':0,'16b':0,'4h':1,'8h':1,'2s':2,'4s':2,'1d':3,'2d':3 };
    const Qenc  = { '8b':0,'16b':1,'4h':0,'8h':1,'2s':0,'4s':1,'1d':0,'2d':1 };
    const arr = m0[2].toLowerCase();
    const size = arrEnc[arr]; const Q = Qenc[arr];
    if (size === undefined) throw new Error(`Unknown arrangement: ${arr}`);
    const Rd = parseInt(m0[1]), Rn = parseInt(m1[1]), Rm = parseInt(m2[1]);
    return ((Q<<30)|(U<<29)|(0b01110<<24)|(size<<22)|(1<<21)|
            (Rm<<16)|(opc<<11)|(1<<10)|(Rn<<5)|Rd) >>> 0;
}

function encNarrowingShift(mnemonic, ops) {

    const base = mnemonic.replace(/2$/, '');
    const isQ2 = mnemonic.endsWith('2');

    const m0 = ops[0].match(/^v(\d+)\.([0-9a-z]+)$/i);
    const m1 = ops[1].match(/^v(\d+)\.([0-9a-z]+)$/i);
    if (!m0 || !m1) throw new Error(`Bad operands: ${ops[0]}, ${ops[1]}`);
    const Rd = parseInt(m0[1]), Rn = parseInt(m1[1]);
    const dstArr = m0[2].toLowerCase();
    const shift = parseInt(ops[2].replace('#',''));

    const esizeMap = { '8b':8,'16b':8,'4h':16,'8h':16,'2s':32,'4s':32 };
    const esize = esizeMap[dstArr];
    if (!esize) throw new Error(`Bad narrowing dst: ${dstArr}`);
    const Q = isQ2 ? 1 : 0;

    const immhb = esize * 2 - shift;
    if (immhb < esize || immhb >= esize * 2) throw new Error(`Shift out of range: ${shift}`);
    const immh = (immhb >> 3) & 0xf;
    const immb = immhb & 7;

    const table = {
        shrn:     [0x10, 0], sqshrun:  [0x10, 1],
        rshrn:    [0x11, 0], sqrshrun: [0x11, 1],
        sqshrn:   [0x12, 0], uqshrn:   [0x12, 1],
        sqrshrn:  [0x13, 0], uqrshrn:  [0x13, 1],
    };
    const inf = table[base];
    if (!inf) throw new Error(`Unknown narrowing shift: ${mnemonic}`);
    const [opc, U] = inf;

    return ((Q<<30)|(U<<29)|(0b011110<<23)|(immh<<19)|(immb<<16)|
            (opc<<11)|(1<<10)|(Rn<<5)|Rd) >>> 0;
}

function encSatShiftImm(mnemonic, ops) {
    const m0 = ops[0].match(/^v(\d+)\.([0-9a-z]+)$/i);
    const m1 = ops[1].match(/^v(\d+)\.([0-9a-z]+)$/i);
    if (!m0 || !m1) throw new Error(`Bad operands`);
    const Rd = parseInt(m0[1]), Rn = parseInt(m1[1]);
    const arr = m0[2].toLowerCase();
    const shift = parseInt(ops[2].replace('#',''));

    const esizeMap = { '8b':8,'16b':8,'4h':16,'8h':16,'2s':32,'4s':32,'1d':64,'2d':64 };
    const QMap    = { '8b':0,'16b':1,'4h':0,'8h':1,'2s':0,'4s':1,'1d':0,'2d':1 };
    const esize = esizeMap[arr], Q = QMap[arr];
    if (!esize) throw new Error(`Bad arrangement: ${arr}`);

    const immhb = esize + shift;
    const immh = (immhb >> 3) & 0xf;
    const immb = immhb & 7;

    let opc, U;
    if (mnemonic === 'sqshl')  { opc = 0x0e; U = 0; }
    else if (mnemonic === 'uqshl')  { opc = 0x0e; U = 1; }
    else if (mnemonic === 'sqshlu') { opc = 0x0c; U = 1; }
    else throw new Error(`Unknown sat shift imm: ${mnemonic}`);

    return ((Q<<30)|(U<<29)|(0b011110<<23)|(immh<<19)|(immb<<16)|
            (opc<<11)|(1<<10)|(Rn<<5)|Rd) >>> 0;
}

function isScalarSimdOperand(op) {
    return /^[bdhsq]\d+$/.test((op || '').toLowerCase());
}

function vecOrScalarSimd(vecFn, scalarFn) {
    return (mnemonic, ops) =>
        isVectorOperand(ops[0]) ? vecFn(mnemonic, ops) : scalarFn(mnemonic, ops);
}

function gprOrVecOrScalarSimd(gprFn, vecFn, scalarFn) {
    return (mnemonic, ops, instruction, littleEndian) => {
        if (isVectorOperand(ops[0])) return vecFn(mnemonic, ops);
        if (isScalarSimdOperand(ops[0])) return scalarFn(mnemonic, ops);
        return gprFn(mnemonic, ops, instruction, littleEndian);
    };
}

function encPac(mnemonic, ops) {
    const info = {
        'pacia': { opc5: 0, noRn: false }, 'pacib': { opc5: 1, noRn: false },
        'pacda': { opc5: 2, noRn: false }, 'pacdb': { opc5: 3, noRn: false },
        'autia': { opc5: 4, noRn: false }, 'autib': { opc5: 5, noRn: false },
        'autda': { opc5: 6, noRn: false }, 'autdb': { opc5: 7, noRn: false },
        'paciza': { opc5: 8, noRn: true }, 'pacizb': { opc5: 9, noRn: true },
        'pacdza': { opc5: 10, noRn: true }, 'pacdzb': { opc5: 11, noRn: true },
        'autiza': { opc5: 12, noRn: true }, 'autizb': { opc5: 13, noRn: true },
        'autdza': { opc5: 14, noRn: true }, 'autdzb': { opc5: 15, noRn: true },
        'xpaci': { opc5: 16, noRn: true }, 'xpacd': { opc5: 17, noRn: true },
    };
    let inf = info[mnemonic];
    if (!inf) throw new Error(`Unknown PAC instruction: ${mnemonic}`);
    let Rd = parseInt(ops[0].replace(/^x/, ''), 10);
    let Rn = inf.noRn ? 31 : parseInt(ops[1].replace(/^x/, ''), 10);
    return (0xDAC10000 | (inf.opc5 << 10) | (Rn << 5) | Rd) >>> 0;
}

function encAuthBranch(mnemonic, ops) {
    let m = mnemonic.match(/^(br|blr)a([ab])(z)?$/);
    if (!m) throw new Error(`Unknown authenticated branch instruction: ${mnemonic}`);
    let link = m[1] === 'blr', key = m[2], isZ = m[3] === 'z';
    let opc = (link ? 1 : 0) | (isZ ? 0 : 8);
    let op3 = 0b000010 | (key === 'b' ? 1 : 0);
    let rn = parseInt(ops[0].replace(/^x/i, ''), 10);
    let rm = 31;
    if (!isZ) {
        let rmOp = ops[1].toLowerCase();
        rm = rmOp === 'sp' ? 31 : parseInt(rmOp.replace(/^x/i, ''), 10);
    }
    return (0xd61f0000 | (opc << 21) | (op3 << 10) | (rn << 5) | rm) >>> 0;
}

function encIrg(mnemonic, ops) {
    let Rd = parseInt(ops[0].replace(/^x/, ''), 10);
    let Rn = parseInt(ops[1].replace(/^x/, ''), 10);
    let Rm = ops[2] ? parseInt(ops[2].replace(/^x/, ''), 10) : 31;
    return (0x9AC01000 | (Rm << 16) | (Rn << 5) | Rd) >>> 0;
}

function encGmi(mnemonic, ops) {
    let Rd = parseInt(ops[0].replace(/^x/, ''), 10);
    let Rn = parseInt(ops[1].replace(/^x/, ''), 10);
    let Rm = parseInt(ops[2].replace(/^x/, ''), 10);
    return (0x9AC01400 | (Rm << 16) | (Rn << 5) | Rd) >>> 0;
}

function encAddSubG(mnemonic, ops) {

    let Rd = parseInt(ops[0].replace(/^x/, ''), 10);
    let Rn = parseInt(ops[1].replace(/^x/, ''), 10);
    let offset = parseImm(ops[2]);
    let uimm4 = parseImm(ops[3]);
    if (offset % 16 !== 0 || offset < 0 || offset > 1008) throw new Error(`ADDG/SUBG immediate must be a multiple of 16 in [0, 1008]: ${offset}`);
    let uimm6 = offset / 16;
    if (uimm4 < 0 || uimm4 > 15) throw new Error(`ADDG/SUBG uimm4 out of range: ${uimm4}`);
    let base = mnemonic === 'subg' ? 0xD1800000 : 0x91800000;

    return (base | (uimm6 << 16) | (uimm4 << 10) | (Rn << 5) | Rd) >>> 0;
}

function encTagLoadStore(mnemonic, ops) {

    const opcMap = { 'ldg': 1, 'stg': 0, 'stzg': 1, 'st2g': 2, 'stz2g': 3 };
    const isLdg = mnemonic === 'ldg';

    let addrStr = ops.slice(1).join(', ');
    let postM = addrStr.match(/^\[([xs]p|x\d+)\],\s*#?([+-]?(?:0x[0-9a-f]+|\d+))$/);
    let preM  = addrStr.match(/^\[([xs]p|x\d+),\s*#?([+-]?(?:0x[0-9a-f]+|\d+))\]!$/);
    let offM  = addrStr.match(/^\[([xs]p|x\d+)(?:,\s*#?([+-]?(?:0x[0-9a-f]+|\d+)))?\]$/);

    let mode, rnStr, offsetBytes;
    if (postM)     { mode = 1; rnStr = postM[1]; offsetBytes = parseImm(postM[2]); }
    else if (preM) { mode = 3; rnStr = preM[1];  offsetBytes = parseImm(preM[2]); }
    else if (offM) { mode = isLdg ? 0 : 2; rnStr = offM[1]; offsetBytes = parseImm(offM[2] || '0'); }
    else throw new Error(`Unrecognised address mode for ${mnemonic}: ${addrStr}`);

    let simm9 = offsetBytes / 16;
    if (!Number.isInteger(simm9) || simm9 < -256 || simm9 > 255)
        throw new Error(`${mnemonic} offset must be a multiple of 16 in [-4096, 4080]`);

    let Rn = rnStr === 'sp' ? 31 : parseInt(rnStr.replace(/^x/, ''), 10);
    let RtStr = ops[0].toLowerCase();
    let Rt = RtStr === 'sp' ? 31 : parseInt(RtStr.replace(/^x/, ''), 10);

    let opc = opcMap[mnemonic];
    let imm9Enc = simm9 & 0x1ff;

    return (0xD9200000 | (opc << 22) | (imm9Enc << 12) | (mode << 10) | (Rn << 5) | Rt) >>> 0;
}

function encStpLdp(mnemonic, ops) {
    if (mnemonic === 'stnp' || mnemonic === 'ldnp') {
        let rt0 = ops[0].toLowerCase();
        let isSimd = /^[sdq]\d+$/.test(rt0);
        let memText = ops[2];
        let m = memText.match(/^\[(sp|x\d+)(?:,\s*#?([+-]?(?:0x[0-9a-f]+|\d+)))?\]$/);
        if (!m) throw new Error(`${mnemonic} only supports the no-offset addressing mode: ${memText}`);
        let rn = m[1] === 'sp' ? 31 : parseReg(m[1]).num;
        let offset = parseImm(m[2] || '0');
        let l = mnemonic === 'ldnp' ? 1 : 0;
        if (isSimd) {
            let rt = parseSimdReg(ops[0]), rt2 = parseSimdReg(ops[1]);
            let opc = rt.prefix === 's' ? 0 : rt.prefix === 'd' ? 1 : 2;
            let scale = opc === 0 ? 2 : opc === 1 ? 3 : 4;
            requireAligned(offset, 1 << scale, mnemonic);
            let imm7 = offset >> scale;
            requireRange(imm7, 7, true, mnemonic);
            return ((opc << 30) | 0x2c000000 | (1 << 26) | (l << 22) | ((imm7 & 0x7f) << 15) | (rt2.num << 10) | (rn << 5) | rt.num) >>> 0;
        }
        let rt = parseReg(ops[0]), rt2 = parseReg(ops[1]);
        let is64 = rt.size === 64;
        let scale = is64 ? 3 : 2;
        requireAligned(offset, 1 << scale, mnemonic);
        let imm7 = offset >> scale;
        requireRange(imm7, 7, true, mnemonic);
        return (((is64 ? 2 : 0) << 30) | 0x28000000 | (l << 22) | ((imm7 & 0x7f) << 15) | (rt2.num << 10) | (rn << 5) | rt.num) >>> 0;
    }
    let rt0 = ops[0].toLowerCase();
    let isSimd = /^[sdq]\d+$/.test(rt0);
    let memText = ops[2] + (ops[3] ? `, ${ops[3]}` : '');
    let pre = memText.match(/^\[(sp|x\d+)(?:,\s*#?([+-]?(?:0x[0-9a-f]+|\d+)))?\]!$/);
    let post = memText.match(/^\[(sp|x\d+)\],\s*#?([+-]?(?:0x[0-9a-f]+|\d+))$/);
    let unsigned = memText.match(/^\[(sp|x\d+)(?:,\s*#?([+-]?(?:0x[0-9a-f]+|\d+)))?\]$/);
    let mode, rnText, offset;
    if (post) { mode = 1; rnText = post[1]; offset = parseImm(post[2]); }
    else if (pre) { mode = 3; rnText = pre[1]; offset = parseImm(pre[2] || '0'); }
    else if (unsigned) { mode = 2; rnText = unsigned[1]; offset = parseImm(unsigned[2] || '0'); }
    else throw new Error(`Unsupported address mode: ${memText}`);
    let rn = rnText === 'sp' ? 31 : parseReg(rnText).num;
    if (isSimd) {
        let rt = parseSimdReg(ops[0]), rt2 = parseSimdReg(ops[1]);
        if (rt.prefix !== rt2.prefix) throw new Error('Register size mismatch');
        let opcSize = rt.prefix === 's' ? 0 : rt.prefix === 'd' ? 1 : 2;
        let scale = opcSize === 0 ? 2 : opcSize === 1 ? 3 : 4;
        requireAligned(offset, 1 << scale, mnemonic);
        let imm7 = offset >> scale;
        requireRange(imm7, 7, true, mnemonic);
        return (opcSize << 30) | 0x2c000000 | (mode << 23) |
            (mnemonic === 'ldp' ? 1 << 22 : 0) | ((imm7 & 0x7f) << 15) |
            (rt2.num << 10) | (rn << 5) | rt.num;
    }
    let rt = parseReg(ops[0]), rt2 = parseReg(ops[1]);
    if (mnemonic === 'ldpsw') {
        let scale = 2;
        requireAligned(offset, 1 << scale, mnemonic);
        let imm7 = offset >> scale;
        requireRange(imm7, 7, true, mnemonic);
        return ((1 << 30) | 0x28000000 | (mode << 23) | (1 << 22) | ((imm7 & 0x7f) << 15) |
            (rt2.num << 10) | (rn << 5) | rt.num) >>> 0;
    }
    let is64 = rt.size === 64;
    let scale = is64 ? 3 : 2;
    requireAligned(offset, 1 << scale, mnemonic);
    let imm7 = offset >> scale;
    if (rt.size !== rt2.size) throw new Error('Register size mismatch');
    requireRange(imm7, 7, true, mnemonic);
    return ((is64 ? 2 : 0) << 30) | 0x28000000 | (mode << 23) |
        (mnemonic === 'ldp' ? 1 << 22 : 0) | ((imm7 & 0x7f) << 15) |
        (rt2.num << 10) | (rn << 5) | rt.num;
}

function encShiftOrRotate(mnemonic, ops) {

    let isImm = ops[2] && ops[2].startsWith('#');
    if (mnemonic === 'ror') {
        return isImm ? encRorImm(mnemonic, ops) : encDataProc2Source(mnemonic, ops);
    }
    return isImm ? encShiftImm(mnemonic, ops) : encDataProc2Source(mnemonic, ops);
}

const map = new Map([
    ['ret', encRet], ['br', encBr], ['blr', encBlr], ['brk', encBrk], ['svc', encSvc],
    ['dmb', encBarrier], ['dsb', encBarrier], ['isb', encIsb], ['clrex', encClrex],
    ['dc', encDcIc], ['ic', encDcIc],
    ['mrs', encMrsMsr], ['msr', encMrsMsr],
    ['b', encBranch], ['bl', encBranch],
    ['adr', encAdr], ['adrp', encAdr],
    ['movz', encMovWide], ['movn', encMovWide], ['movk', encMovWide],
    ['mov', (mnemonic, ops) => {
        if (/^v\d+\.[bhsd]\[\d+\]$/i.test(ops[0] || '')) return encAdvSimdCopy('ins', ops);
        if (/^v\d+\.[bhsd]\[\d+\]$/i.test(ops[1] || '')) return encAdvSimdCopy('mov', ops);
        if (isVectorOperand(ops[0]) && isVectorOperand(ops[1])) return encAdvSimd3Same('orr', [ops[0], ops[1], ops[1]]);
        return encMov(mnemonic, ops);
    }],
    ['cinc', encCondAlias], ['cinv', encCondAlias], ['cneg', encCondAlias],
    ['cset', encCset], ['csetm', encCset],
    ['csel', encCsel], ['csinc', encCsel], ['csinv', encCsel], ['csneg', encCsel],
    ['ccmp', encCcmp], ['ccmn', encCcmp],
    ['adc', encAdcSbc], ['adcs', encAdcSbc], ['sbc', encAdcSbc], ['sbcs', encAdcSbc],
    ['ngc', encNgc], ['ngcs', encNgc],
    ['neg', encNeg], ['negs', encNeg],
    ['udiv', encDataProc2Source], ['sdiv', encDataProc2Source],
    ['lslv', encDataProc2Source], ['lsrv', encDataProc2Source], ['asrv', encDataProc2Source], ['rorv', encDataProc2Source],
    ['lsl', encShiftOrRotate], ['lsr', encShiftOrRotate], ['asr', encShiftOrRotate], ['ror', encShiftOrRotate],
    ['mul', encMul3Source], ['mneg', encMul3Source], ['madd', encMul3Source], ['msub', encMul3Source],
    ['smull', encMulLong], ['smnegl', encMulLong], ['smaddl', encMulLong], ['smsubl', encMulLong],
    ['umull', encMulLong], ['umnegl', encMulLong], ['umaddl', encMulLong], ['umsubl', encMulLong],
    ['smulh', encMulh], ['umulh', encMulh],
    ['extr', encExtr],
    ['clz', encDataProc1SourceBit], ['cls', encDataProc1SourceBit], ['rbit', encDataProc1SourceBit],
    ['rev', encDataProc1SourceBit], ['rev16', encDataProc1SourceBit], ['rev32', encDataProc1SourceBit], ['rev64', encDataProc1SourceBit],
    ['ldxr', encLoadStoreExclusive], ['ldxrb', encLoadStoreExclusive], ['ldxrh', encLoadStoreExclusive],
    ['stxr', encLoadStoreExclusive], ['stxrb', encLoadStoreExclusive], ['stxrh', encLoadStoreExclusive],
    ['ldaxr', encLoadStoreExclusive], ['ldaxrb', encLoadStoreExclusive], ['ldaxrh', encLoadStoreExclusive],
    ['stlxr', encLoadStoreExclusive], ['stlxrb', encLoadStoreExclusive], ['stlxrh', encLoadStoreExclusive],
    ['ldxp', encLoadStoreExclusive], ['stxp', encLoadStoreExclusive],
    ['ldaxp', encLoadStoreExclusive], ['stlxp', encLoadStoreExclusive],
    ['ldar', encLoadStoreExclusive], ['ldarb', encLoadStoreExclusive], ['ldarh', encLoadStoreExclusive],
    ['stlr', encLoadStoreExclusive], ['stlrb', encLoadStoreExclusive], ['stlrh', encLoadStoreExclusive],
    ['ldlar', encLoadStoreExclusive], ['ldlarb', encLoadStoreExclusive], ['ldlarh', encLoadStoreExclusive],
    ['stllr', encLoadStoreExclusive], ['stllrb', encLoadStoreExclusive], ['stllrh', encLoadStoreExclusive],
    ['sbfx', encBitfield], ['ubfx', encBitfield], ['sbfiz', encBitfield], ['ubfiz', encBitfield],
    ['bfi', encBitfield], ['bfxil', encBitfield], ['bfc', encBitfield],
    ['sbfm', encBitfieldRaw], ['ubfm', encBitfieldRaw], ['bfm', encBitfieldRaw],
    ['sxtb', encExtend], ['sxth', encExtend], ['sxtw', encExtend], ['uxtb', encExtend], ['uxth', encExtend],
    ['adds', encArithOrLogical], ['subs', encArithOrLogical],
    ['ands', encArithOrLogical],
    ['orn', encArithOrLogical], ['eon', encArithOrLogical], ['bics', encArithOrLogical],
    ['cmp', encArithOrLogical], ['cmn', encArithOrLogical], ['tst', encArithOrLogical], ['mvn', encArithOrLogical],
    ['cbz', encCbz], ['cbnz', encCbz],
    ['tbz', encTbz], ['tbnz', encTbz],
    ['ldrsw', (m, ops) => (ops[1] && ops[1].startsWith('#')) ? encLdrLiteral(m, ops) : encLoadStore(m, ops)],
    ['ldr', (m, ops) => (ops[1] && ops[1].startsWith('#')) ? encLdrLiteral(m, ops) : encLoadStore(m, ops)],
    ['str', encLoadStore], ['ldur', encLoadStore], ['stur', encLoadStore], ['prfm', encPrfm],
    ['ldrb', encLoadStore], ['strb', encLoadStore], ['ldurb', encLoadStore], ['sturb', encLoadStore],
    ['ldrh', encLoadStore], ['strh', encLoadStore], ['ldurh', encLoadStore], ['sturh', encLoadStore],
    ['ldrsb', encLoadStore], ['ldursb', encLoadStore], ['ldrsh', encLoadStore], ['ldursh', encLoadStore], ['ldursw', encLoadStore],
    ['stp', encStpLdp], ['ldp', encStpLdp], ['ldpsw', encStpLdp],
    ['stnp', encStpLdp], ['ldnp', encStpLdp],
    ['fmaxnm', vecOrScalar(encFpArith, encAdvSimd3Same)], ['fminnm', vecOrScalar(encFpArith, encAdvSimd3Same)], ['fnmul', encFpArith],
    ['fcmp', encFcmp], ['fcmpe', encFcmp],
    ['fccmp', encFccmp], ['fccmpe', encFccmp],
    ['fcsel', encFcsel],
    ['fabs', encFp1Source], ['fneg', encFp1Source], ['fsqrt', encFp1Source],
    ['frintn', vecOrScalar(encFp1Source, encAdvSimd2RegMisc)], ['frintp', vecOrScalar(encFp1Source, encAdvSimd2RegMisc)],
    ['frintm', vecOrScalar(encFp1Source, encAdvSimd2RegMisc)], ['frintz', vecOrScalar(encFp1Source, encAdvSimd2RegMisc)],
    ['frinta', vecOrScalar(encFp1Source, encAdvSimd2RegMisc)], ['frintx', vecOrScalar(encFp1Source, encAdvSimd2RegMisc)],
    ['frinti', vecOrScalar(encFp1Source, encAdvSimd2RegMisc)],
    ['fcvt', encFcvt],
    ['scvtf', encScvtfUcvtf], ['ucvtf', encScvtfUcvtf],
    ['fmadd', encFmadd], ['fmsub', encFmadd], ['fnmadd', encFmadd], ['fnmsub', encFmadd],
    ['fmov', encFmov],
    ['dup', (mnemonic, ops) => /^v\d+\.[bhsd]\[\d+\]$/i.test(ops[1] || '') ? encAdvSimdCopy(mnemonic, ops) : encDup(mnemonic, ops)],
    ['ins', encAdvSimdCopy], ['umov', encAdvSimdCopy], ['smov', encAdvSimdCopy],
    ['movi', encMovi], ['mvni', encMovi],
    ['and', vecOrScalar(encArithOrLogical, encAdvSimd3Same)],
    ['orr', vecOrScalar(encArithOrLogical, encAdvSimd3Same)],
    ['eor', vecOrScalar(encArithOrLogical, encAdvSimd3Same)],
    ['bic', vecOrScalar(encArithOrLogical, encAdvSimd3Same)],
    ['orn', vecOrScalar(encArithOrLogical, encAdvSimd3Same)],
    ['add', vecOrScalar(encArithOrLogical, encAdvSimd3Same)],
    ['sub', vecOrScalar(encArithOrLogical, encAdvSimd3Same)],
    ['mul', vecOrScalar(encMul3Source, encAdvSimd3Same)],
    ['fadd', vecOrScalar(encFpArith, encAdvSimd3Same)],
    ['fsub', vecOrScalar(encFpArith, encAdvSimd3Same)],
    ['fmul', vecOrScalar(encFpArith, encAdvSimd3Same)],
    ['fdiv', vecOrScalar(encFpArith, encAdvSimd3Same)],
    ['fmax', vecOrScalar(encFpArith, encAdvSimd3Same)],
    ['fmin', vecOrScalar(encFpArith, encAdvSimd3Same)],

    ['bsl', encAdvSimd3Same], ['bit', encAdvSimd3Same], ['bif', encAdvSimd3Same],
    ['mla', encAdvSimd3Same], ['mls', encAdvSimd3Same],
    ['cmtst', encAdvSimd3Same], ['cmeq', encAdvSimd3Same], ['cmgt', encAdvSimd3Same], ['cmhi', encAdvSimd3Same],
    ['cmge', encAdvSimd3Same], ['cmhs', encAdvSimd3Same],
    ['smax', encAdvSimd3Same], ['smin', encAdvSimd3Same], ['umax', encAdvSimd3Same], ['umin', encAdvSimd3Same],
    ['smaxp', encAdvSimd3Same], ['sminp', encAdvSimd3Same], ['umaxp', encAdvSimd3Same], ['uminp', encAdvSimd3Same],
    ['addp', (mnemonic, ops) => isScalarSimdOperand(ops[0]) ? encAdvSimdScalarPairwise(mnemonic, ops) : encAdvSimd3Same(mnemonic, ops)],
    ['faddp', encAdvSimd3Same], ['fabd', encAdvSimd3Same],
    ['shadd', encAdvSimd3Same], ['uhadd', encAdvSimd3Same],
    ['srhadd', encAdvSimd3Same], ['urhadd', encAdvSimd3Same],
    ['shsub', encAdvSimd3Same], ['uhsub', encAdvSimd3Same],
    ['sabd', encAdvSimd3Same], ['uabd', encAdvSimd3Same],
    ['saba', encAdvSimd3Same], ['uaba', encAdvSimd3Same],
    ['sdot', encAdvSimdDot], ['udot', encAdvSimdDot],
    ['sshl', vecOrScalarSimd(encAdvSimd3Same, encAdvSimdScalar3Same)],
    ['ushl', vecOrScalarSimd(encAdvSimd3Same, encAdvSimdScalar3Same)],
    ['fmla', encAdvSimd3Same], ['fmls', encAdvSimd3Same],
    ['fcmeq', encAdvSimd3Same], ['fcmge', encAdvSimd3Same], ['fcmgt', encAdvSimd3Same],

    ['zip1', encPermute], ['zip2', encPermute],
    ['uzp1', encPermute], ['uzp2', encPermute],
    ['trn1', encPermute], ['trn2', encPermute],

    ['tbl', encTblTbx], ['tbx', encTblTbx],

    ['ext', encExt],

    ['addv', encAcrossLanes], ['smaxv', encAcrossLanes],
    ['sminv', encAcrossLanes], ['umaxv', encAcrossLanes],
    ['uminv', encAcrossLanes], ['uaddlv', encAcrossLanes], ['saddlv', encAcrossLanes],

    ['fmaxv', encFpAcrossLanes], ['fminv', encFpAcrossLanes],
    ['fmaxnmv', encFpAcrossLanes], ['fminnmv', encFpAcrossLanes],

    ['shl', vecOrScalarSimd(encShiftByImm, encAdvSimdScalarShiftByImm)], ['sli', vecOrScalarSimd(encShiftByImm, encAdvSimdScalarShiftByImm)],
    ['sshr', vecOrScalarSimd(encShiftByImm, encAdvSimdScalarShiftByImm)], ['ushr', vecOrScalarSimd(encShiftByImm, encAdvSimdScalarShiftByImm)],
    ['ssra', vecOrScalarSimd(encShiftByImm, encAdvSimdScalarShiftByImm)], ['usra', vecOrScalarSimd(encShiftByImm, encAdvSimdScalarShiftByImm)],
    ['srshr', vecOrScalarSimd(encShiftByImm, encAdvSimdScalarShiftByImm)], ['urshr', vecOrScalarSimd(encShiftByImm, encAdvSimdScalarShiftByImm)],
    ['srsra', vecOrScalarSimd(encShiftByImm, encAdvSimdScalarShiftByImm)], ['ursra', vecOrScalarSimd(encShiftByImm, encAdvSimdScalarShiftByImm)],
    ['sri', vecOrScalarSimd(encShiftByImm, encAdvSimdScalarShiftByImm)],

    ['sshll', encSshllUshll], ['ushll', encSshllUshll],
    ['sshll2', encSshllUshll], ['ushll2', encSshllUshll],
    ['sxtl', encSshllUshll], ['uxtl', encSshllUshll],
    ['sxtl2', encSshllUshll], ['uxtl2', encSshllUshll],
    ['shrn', encShrn], ['rshrn', encShrn],
    ['shrn2', encShrn], ['rshrn2', encShrn],

    ['add', gprOrVecOrScalarSimd(encArithOrLogical, encAdvSimd3Same, encAdvSimdScalar3Same)],
    ['sub', gprOrVecOrScalarSimd(encArithOrLogical, encAdvSimd3Same, encAdvSimdScalar3Same)],
    ['cmtst', vecOrScalarSimd(encAdvSimd3Same, encAdvSimdScalar3Same)],
    ['cmeq', vecOrScalarSimd(encAdvSimd3Same, encAdvSimdScalar3Same)],
    ['cmgt', vecOrScalarSimd(encAdvSimd3Same, encAdvSimdScalar3Same)],
    ['cmhi', vecOrScalarSimd(encAdvSimd3Same, encAdvSimdScalar3Same)],
    ['cmge', vecOrScalarSimd(encAdvSimd3Same, encAdvSimdScalar3Same)],
    ['cmhs', vecOrScalarSimd(encAdvSimd3Same, encAdvSimdScalar3Same)],

    ['pacia', encPac], ['pacib', encPac], ['pacda', encPac], ['pacdb', encPac],
    ['autia', encPac], ['autib', encPac], ['autda', encPac], ['autdb', encPac],
    ['paciza', encPac], ['pacizb', encPac], ['pacdza', encPac], ['pacdzb', encPac],
    ['autiza', encPac], ['autizb', encPac], ['autdza', encPac], ['autdzb', encPac],
    ['xpaci', encPac], ['xpacd', encPac],
    ['braa', encAuthBranch], ['brab', encAuthBranch], ['blraa', encAuthBranch], ['blrab', encAuthBranch],
    ['braaz', encAuthBranch], ['brabz', encAuthBranch], ['blraaz', encAuthBranch], ['blrabz', encAuthBranch],

    ['irg', encIrg], ['gmi', encGmi],
    ['addg', encAddSubG], ['subg', encAddSubG],

    ['ldg', encTagLoadStore],
    ['stg', encTagLoadStore], ['stzg', encTagLoadStore],
    ['ldapr', encLdapr], ['ldaprb', encLdapr], ['ldaprh', encLdapr],
    ['st2g', encTagLoadStore], ['stz2g', encTagLoadStore],

    ['xtn', encNarrowingConvert], ['xtn2', encNarrowingConvert],
    ['sqxtn', encNarrowingConvert], ['sqxtn2', encNarrowingConvert],
    ['sqxtun', encNarrowingConvert], ['sqxtun2', encNarrowingConvert],
    ['uqxtn', encNarrowingConvert], ['uqxtn2', encNarrowingConvert],
    ['fcvtn', encNarrowingConvert], ['fcvtn2', encNarrowingConvert],
    ['fcvtl', encNarrowingConvert], ['fcvtl2', encNarrowingConvert],
    ['fcvtxn', encNarrowingConvert], ['fcvtxn2', encNarrowingConvert],

    ['sqadd', encSaturating3Same], ['uqadd', encSaturating3Same],
    ['sqsub', encSaturating3Same], ['uqsub', encSaturating3Same],

    ['shrn',     encNarrowingShift], ['shrn2',     encNarrowingShift],
    ['rshrn',    encNarrowingShift], ['rshrn2',    encNarrowingShift],
    ['sqshrun',  encNarrowingShift], ['sqshrun2',  encNarrowingShift],
    ['sqrshrun', encNarrowingShift], ['sqrshrun2', encNarrowingShift],
    ['sqshrn',   encNarrowingShift], ['sqshrn2',   encNarrowingShift],
    ['uqshrn',   encNarrowingShift], ['uqshrn2',   encNarrowingShift],
    ['sqrshrn',  encNarrowingShift], ['sqrshrn2',  encNarrowingShift],
    ['uqrshrn',  encNarrowingShift], ['uqrshrn2',  encNarrowingShift],

    ['sqshlu', (mnemonic, ops) => isScalarSimdOperand(ops[0]) ? encAdvSimdScalarShiftByImm(mnemonic, ops) : encSatShiftImm(mnemonic, ops)],
]);

for (const m of ['saddl', 'saddl2', 'uaddl', 'uaddl2', 'ssubl', 'ssubl2', 'usubl', 'usubl2',
                  'saddw', 'saddw2', 'uaddw', 'uaddw2', 'ssubw', 'ssubw2', 'usubw', 'usubw2',
                  'addhn', 'addhn2', 'raddhn', 'raddhn2', 'subhn', 'subhn2', 'rsubhn', 'rsubhn2',
                  'sabal', 'sabal2', 'uabal', 'uabal2', 'sabdl', 'sabdl2', 'uabdl', 'uabdl2',
                  'smlal', 'smlal2', 'umlal', 'umlal2', 'smlsl', 'smlsl2', 'umlsl', 'umlsl2',
                  'smull2', 'umull2', 'pmull', 'pmull2']) {
    map.set(m, encAdvSimd3Different);
}
map.set('smull', (mnemonic, ops) => {
    if (isIndexedSimdOperand(ops[2])) return encAdvSimdVectorByElement(mnemonic, ops);
    return isVectorOperand(ops[1]) ? encAdvSimd3Different(mnemonic, ops) : encMulLong(mnemonic, ops);
});
map.set('umull', (mnemonic, ops) => {
    if (isIndexedSimdOperand(ops[2])) return encAdvSimdVectorByElement(mnemonic, ops);
    return isVectorOperand(ops[1]) ? encAdvSimd3Different(mnemonic, ops) : encMulLong(mnemonic, ops);
});

function isIndexedSimdOperand(op) {
    return /^v\d+\.[bhsd]\[\d+\]$/i.test(op || '');
}

map.set('mul', (mnemonic, ops) => {
    if (isIndexedSimdOperand(ops[2])) return encAdvSimdVectorByElement(mnemonic, ops);
    if (isVectorOperand(ops[0])) return encAdvSimd3Same(mnemonic, ops);
    return encMul3Source(mnemonic, ops);
});
map.set('mla', (mnemonic, ops) =>
    isIndexedSimdOperand(ops[2]) ? encAdvSimdVectorByElement(mnemonic, ops) : encAdvSimd3Same(mnemonic, ops));
map.set('mls', (mnemonic, ops) =>
    isIndexedSimdOperand(ops[2]) ? encAdvSimdVectorByElement(mnemonic, ops) : encAdvSimd3Same(mnemonic, ops));
map.set('fmul', (mnemonic, ops) => {
    if (isIndexedSimdOperand(ops[2])) return encAdvSimdVectorByElement(mnemonic, ops);
    if (isVectorOperand(ops[0])) return encAdvSimd3Same(mnemonic, ops);
    return encFpArith(mnemonic, ops);
});
map.set('fmla', (mnemonic, ops) =>
    isIndexedSimdOperand(ops[2]) ? encAdvSimdVectorByElement(mnemonic, ops) : encAdvSimd3Same(mnemonic, ops));
map.set('fmls', (mnemonic, ops) =>
    isIndexedSimdOperand(ops[2]) ? encAdvSimdVectorByElement(mnemonic, ops) : encAdvSimd3Same(mnemonic, ops));

for (const m of ['smull2', 'umull2', 'smlal', 'umlal', 'smlal2', 'umlal2',
                  'smlsl', 'umlsl', 'smlsl2', 'umlsl2', 'sqdmull', 'sqdmull2']) {
    map.set(m, (mnemonic, ops) =>
        isIndexedSimdOperand(ops[2]) ? encAdvSimdVectorByElement(mnemonic, ops) : encAdvSimd3Different(mnemonic, ops));
}
map.set('sqdmulh', (mnemonic, ops) =>
    isIndexedSimdOperand(ops[2]) ? encAdvSimdVectorByElement(mnemonic, ops) : encSaturating3Same(mnemonic, ops));
map.set('sqrdmulh', (mnemonic, ops) =>
    isIndexedSimdOperand(ops[2]) ? encAdvSimdVectorByElement(mnemonic, ops) : encSaturating3Same(mnemonic, ops));

function isZeroOperand(op) {
    if (!op) return false;
    let n = parseFloat(op.replace(/^#/, ''));
    return n === 0;
}

map.set('neg', (mnemonic, ops, instruction, littleEndian) => {
    if (isVectorOperand(ops[0])) return encAdvSimd2RegMisc(mnemonic, ops);
    if (isScalarSimdOperand(ops[0])) return encAdvSimdScalar2RegMisc(mnemonic, ops);
    return encNeg(mnemonic, ops);
});
map.set('abs', (mnemonic, ops) =>
    isVectorOperand(ops[0]) ? encAdvSimd2RegMisc(mnemonic, ops) : encAdvSimdScalar2RegMisc(mnemonic, ops));
map.set('cls', (mnemonic, ops) =>
    isVectorOperand(ops[0]) ? encAdvSimd2RegMisc(mnemonic, ops) : encDataProc1SourceBit(mnemonic, ops));
map.set('clz', (mnemonic, ops) =>
    isVectorOperand(ops[0]) ? encAdvSimd2RegMisc(mnemonic, ops) : encDataProc1SourceBit(mnemonic, ops));
map.set('rev16', (mnemonic, ops) =>
    isVectorOperand(ops[0]) ? encAdvSimd2RegMisc(mnemonic, ops) : encDataProc1SourceBit(mnemonic, ops));
map.set('rev32', (mnemonic, ops) =>
    isVectorOperand(ops[0]) ? encAdvSimd2RegMisc(mnemonic, ops) : encDataProc1SourceBit(mnemonic, ops));
map.set('rev64', (mnemonic, ops) =>
    isVectorOperand(ops[0]) ? encAdvSimd2RegMisc(mnemonic, ops) : encDataProc1SourceBit(mnemonic, ops));
map.set('cnt', encAdvSimd2RegMisc);
map.set('not', encAdvSimd2RegMisc);
map.set('fabs', (mnemonic, ops) =>
    isVectorOperand(ops[0]) ? encAdvSimd2RegMisc(mnemonic, ops) : encFp1Source(mnemonic, ops));
map.set('fneg', (mnemonic, ops) =>
    isVectorOperand(ops[0]) ? encAdvSimd2RegMisc(mnemonic, ops) : encFp1Source(mnemonic, ops));
map.set('fsqrt', (mnemonic, ops) =>
    isVectorOperand(ops[0]) ? encAdvSimd2RegMisc(mnemonic, ops) : encFp1Source(mnemonic, ops));
map.set('cmle', (mnemonic, ops) =>
    isVectorOperand(ops[0]) ? encAdvSimd2RegMisc(mnemonic, ops) : encAdvSimdScalar2RegMisc(mnemonic, ops));
map.set('cmlt', (mnemonic, ops) =>
    isVectorOperand(ops[0]) ? encAdvSimd2RegMisc(mnemonic, ops) : encAdvSimdScalar2RegMisc(mnemonic, ops));
map.set('fcmle', (mnemonic, ops) => encAdvSimd2RegMisc(mnemonic, ops));
map.set('fcmlt', (mnemonic, ops) => encAdvSimd2RegMisc(mnemonic, ops));

for (const m of ['cmeq', 'cmgt', 'cmge']) {
    map.set(m, (mnemonic, ops) => {
        let isZero = ops.length === 3 && isZeroOperand(ops[2]);
        if (isVectorOperand(ops[0])) return isZero ? encAdvSimd2RegMisc(mnemonic, ops) : encAdvSimd3Same(mnemonic, ops);
        return isZero ? encAdvSimdScalar2RegMisc(mnemonic, ops) : encAdvSimdScalar3Same(mnemonic, ops);
    });
}
for (const m of ['fcmeq', 'fcmgt', 'fcmge']) {
    map.set(m, (mnemonic, ops) => {
        let isZero = ops.length === 3 && isZeroOperand(ops[2]);
        return isZero ? encAdvSimd2RegMisc(mnemonic, ops) : encAdvSimd3Same(mnemonic, ops);
    });
}

for (const m of ['sqshl', 'uqshl']) {
    map.set(m, (mnemonic, ops) => {
        const op2 = ops[2] || '';
        if (op2.startsWith('#') || /^\d+$/.test(op2)) {
            return isScalarSimdOperand(ops[0]) ? encAdvSimdScalarShiftByImm(mnemonic, ops) : encSatShiftImm(mnemonic, ops);
        }

        return encSaturating3Same(mnemonic, ops);
    });
}

const patternHandlers = [
    [/^b\.\w+$/, encBCond],
    [/^crc32c?[bhwx]$/, encCrc32],
    [/^(cas|casa|casl|casal)[bh]?$/, encCas],
    [/^swp(a|l|al)?[bh]?$/, encSwp],
    [/^ld(add|clr|eor|set|smax|smin|umax|umin)(a|l|al)?[bh]?$/, encAtomicLd],
    [/^fcvt(z|n|p|m|a)[su]$/, encFcvtRound],
    [/^ld[1-4]r$/, encLdNR],

    [/^(ld|st)[1-4]$/, (mnem, ops, inst, le) => {
        if (ops[0] && /\}\[\d+\]$/.test(ops[0])) return encLdStSingle(mnem, ops);
        return encLdStMultiple(mnem, ops);
    }],
];

function encodeArm64(instruction, littleEndian) {
    let { mnemonic, ops } = parseInstruction(instruction);
    let fixedName = ops.length ? `${mnemonic} ${ops.join(', ')}` : mnemonic;
    let enc;

    if (fixedArm64[fixedName] !== undefined) {
        enc = fixedArm64[fixedName];
    } else {
        let handler = map.get(mnemonic);
        if (!handler) {
            for (const [pattern, fn] of patternHandlers) {
                if (pattern.test(mnemonic)) { handler = fn; break; }
            }
        }
        if (!handler) throw new Error('Unsupported instruction: ' + mnemonic);
        enc = handler(mnemonic, ops, instruction, littleEndian);
    }

    enc >>>= 0;
    return littleEndian ? reverseBytes(enc) : enc;
}
