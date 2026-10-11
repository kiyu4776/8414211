
function parseELF64(buf) {
    if (buf.length < 64 || buf.toString('ascii', 0, 4) !== '\x7fELF') return null;
    if (buf[4] !== 2) throw new Error('only ELF64 is supported');
    if (buf[5] !== 1) throw new Error('only little-endian ELF is supported');
    const machine = buf.readUInt16LE(18);
    if (machine !== 183) throw new Error(`ELF machine ${machine} is not AArch64 (183)`);

    const type = buf.readUInt16LE(16);
    const eEntry = readU64(buf, 24);
    const shoff = readU64(buf, 40);
    const shentsize = buf.readUInt16LE(58);
    const shnum = buf.readUInt16LE(60);
    const shstrndx = buf.readUInt16LE(62);
    if (!shoff || !shnum) throw new Error('ELF has no section table');

    const sections = [];
    for (let i = 0; i < shnum; i++) {
        const o = shoff + i * shentsize;
        if (o + 64 > buf.length) throw new Error('truncated ELF section table');
        sections.push({
            index: i,
            nameOffset: buf.readUInt32LE(o),
            type: buf.readUInt32LE(o + 4),
            flags: readU64(buf, o + 8),
            addr: readU64(buf, o + 16),
            offset: readU64(buf, o + 24),
            size: readU64(buf, o + 32),
            link: buf.readUInt32LE(o + 40),
            info: buf.readUInt32LE(o + 44),
            addralign: readU64(buf, o + 48),
            entsize: readU64(buf, o + 56),
        });
    }
    const shstr = sections[shstrndx];
    const shstrBuf = shstr ? buf.subarray(shstr.offset, shstr.offset + shstr.size) : new Bytes(0);
    for (const s of sections) s.name = readCString(shstrBuf, s.nameOffset);

    const text = sections.find(s => s.name === '.text');
    if (!text) throw new Error('ELF has no .text section');
    if (text.offset + text.size > buf.length) throw new Error('truncated .text section');

    const stringsFor = new Map();
    for (const s of sections) {
        if (s.type === 3 && s.size <= buf.length - s.offset) stringsFor.set(s.index, buf.subarray(s.offset, s.offset + s.size));
    }

    const symbols = [];
    for (const s of sections) {
        if (s.type !== 2 && s.type !== 11) continue;
        const strtab = stringsFor.get(s.link) || new Bytes(0);
        const entsize = s.entsize || 24;
        for (let o = s.offset; o + entsize <= s.offset + s.size; o += entsize) {
            const stName = buf.readUInt32LE(o);
            const stInfo = buf[o + 4];
            const stOther = buf[o + 5];
            const stShndx = buf.readUInt16LE(o + 6);
            const stValue = readU64(buf, o + 8);
            const stSize = readU64(buf, o + 16);
            symbols.push({
                tableSection: s.index,
                tableOffset: o,
                index: Math.floor((o - s.offset) / entsize),
                name: readCString(strtab, stName),
                bind: stInfo >>> 4,
                type: stInfo & 0xf,
                other: stOther,
                shndx: stShndx,
                value: stValue,
                size: stSize,
            });
        }
    }

    const relocations = new Map();
    for (const s of sections) {
        if (s.type !== 4 && s.type !== 9) continue;
        if (s.info !== text.index) continue;
        const entsize = s.entsize || (s.type === 4 ? 24 : 16);
        for (let o = s.offset; o + entsize <= s.offset + s.size; o += entsize) {
            const rOffset = readU64(buf, o);
            const rInfoBig = buf.readBigUInt64LE(o + 8);
            const symIndex = Number(rInfoBig >> 32n);
            const rType = Number(rInfoBig & 0xffffffffn);
            const addend = s.type === 4 ? Number(buf.readBigInt64LE(o + 16)) : 0;
            const sym = symbols.find(x => x.tableSection === s.link && x.index === symIndex);
            const sectionSymbolName = sym && !sym.name && sym.shndx < sections.length ? sections[sym.shndx].name : '';
            const relocationSymbol = sym?.name || sectionSymbolName || '';
            const address = text.addr + (rOffset - text.addr);
            relocations.set(address, { offset: rOffset, type: rType, addend, symbol: relocationSymbol, symIndex });
        }
    }

    const rebases = new Map(), binds = new Map(), indirectByAddress = new Map();
    for (const s of sections) {
        if (s.type !== 4 || s.info === text.index) continue;
        const entsize = s.entsize || 24;
        for (let o = s.offset; o + entsize <= s.offset + s.size; o += entsize) {
            const rOffset = readU64(buf, o), rInfo = buf.readBigUInt64LE(o + 8);
            const symIndex = Number(rInfo >> 32n), rType = Number(rInfo & 0xffffffffn);
            const addend = Number(buf.readBigInt64LE(o + 16));
            if (rType === 1027) rebases.set(rOffset, addend);
            else if (rType === 1025 || rType === 1026 || rType === 257) {
                const sym = symbols.find(x => x.tableSection === s.link && x.index === symIndex);
                if (sym?.name) binds.set(rOffset, { symbol: sym.name, addend, type: 1 });
            }
        }
    }

    for (const s of sections) {
        if (!/^\.i?plt/.test(s.name || '') || s.type !== 1 || !s.addr) continue;
        for (let i = 0; i + 8 <= s.size; i += 4) {
            const a = s.addr + i, w = buf.readUInt32LE(s.offset + i);
            if (((w & 0x9f00001f) >>> 0) !== 0x90000010) continue;
            const raw21 = (((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3);
            const delta = (raw21 & 0x100000 ? raw21 - 0x200000 : raw21) * 4096;
            for (let k = 1; k <= 3 && i + 4 * (k + 1) <= s.size; k++) {
                const l = buf.readUInt32LE(s.offset + i + 4 * k);
                if (((l & 0xffc003ff) >>> 0) === 0xf9400211) {
                    const slot = Math.floor(a / 4096) * 4096 + delta + ((l >>> 10) & 0xfff) * 8;
                    const bind = binds.get(slot);
                    if (bind) {
                        indirectByAddress.set(a, { name: bind.symbol });
                        const prev = i >= 4 ? buf.readUInt32LE(s.offset + i - 4) : 0;
                        if (prev === 0xd503245f || prev === 0xd503241f || prev === 0xd50324df) indirectByAddress.set(a - 4, { name: bind.symbol });
                    }
                    break;
                }
            }
        }
    }

    const functionSymbols = symbols
        .filter(s => (s.type === 2 || s.type === 10) && s.shndx === text.index && s.name)
        .sort((a, b) => a.value - b.value);
    const dataSymbols = symbols
        .filter(s => s.name && s.shndx > 0 && s.shndx < 0xff00 && (s.type === 1 || s.type === 6 || s.type === 0) && s.value
            && sections[s.shndx] && !(sections[s.shndx].flags & 0x4) && !s.name.startsWith('$'))
        .map(s => ({ name: s.name, value: s.value, size: s.size || 0 }))
        .sort((a, b) => a.value - b.value);

    const textBytes = Bytes.copy(buf.subarray(text.offset, text.offset + text.size));
    return {
        kind: 'elf',
        dataSymbols,
        rebases,
        binds,
        indirectByAddress,
        type,
        entry: eEntry,
        buffer: buf,
        sections,
        text,
        textBytes,
        symbols,
        functionSymbols,
        relocations,
        imageBase: text.addr,
    };
}
