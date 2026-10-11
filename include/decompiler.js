'use strict';

function parseNum(value) {
    if (typeof value === 'number') return value;
    const s = String(value).trim();
    if (!/^[-+]?(?:0x[0-9a-f]+|\d+)$/i.test(s)) throw new Error(`bad number: ${value}`);
    const n = Number(s.replace(/^[-+]/, ''));
    return s[0] === '-' ? -n : n;
}

function hex(value) {
    const n = Number(value);
    return `0x${(n >>> 0).toString(16).padStart(8, '0')}`;
}

function hex64(value) {
    const n = Number(value);
    return `0x${n.toString(16)}`;
}

function regNorm(s) { return String(s ?? '').trim().toLowerCase(); }
function isZeroReg(s) { return /^(?:x|w)zr$/i.test(String(s).trim()); }
function isSP(s) { return /^(?:sp|wsp)$/i.test(String(s).trim()); }
function isFPRegister(s) { return /^(?:v|q|d|s|h|b)(?:[0-9]|[12][0-9]|3[01])$/i.test(String(s).trim()); }
function isRegister(s) { return /^(?:x|w)(?:\d+|zr)$/i.test(String(s).trim()) || isSP(s) || isFPRegister(s); }
function regIndex(s) {
    const m = /^(?:x|w)(\d+)$/.exec(regNorm(s));
    return m ? Number(m[1]) : null;
}
function canonicalReg(s) {
    const r = regNorm(s);
    const n = regIndex(r);
    if (n != null) return `x${n}`;
    return r;
}
function isCallerSavedReg(r) {
    const n = regIndex(r);
    return n != null && n <= 17;
}
function isCalleeSavedReg(r) {
    if (/^[dq](?:[89]|1[0-5])$/i.test(String(r).trim())) return true;
    const n = regIndex(r);
    return n != null && n >= 19 && n <= 28;
}

function normalizePAC(parts) {
    const m = parts.mnemonic, o = parts.operands;
    if (/^(?:pac|aut)i[ab](?:sp|z|1716)$/.test(m) || /^(?:pac|aut)[id]z?[ab]$/.test(m) || /^xpac(?:i|d|lri)$/.test(m))
        return { mnemonic: 'nop', operands: [], pac: m };
    if (/^blra[ab]z?$/.test(m)) return { mnemonic: 'blr', operands: [o[0]], pac: m };
    if (/^bra[ab]z?$/.test(m)) return { mnemonic: 'br', operands: [o[0]], pac: m };
    if (m === 'retaa' || m === 'retab') return { mnemonic: 'ret', operands: [], pac: m };
    if (/^ldra[ab]$/.test(m)) return { mnemonic: 'ldr', operands: o, pac: m };
    return parts;
}

function splitInstruction(text) {
    if (typeof text !== 'string') return { mnemonic: '', operands: [] };
    const t = text.trim();
    if (!t) return { mnemonic: '', operands: [] };
    const m = /^([^\s]+)(?:\s+(.*))?$/.exec(t);
    if (!m) return { mnemonic: '', operands: [] };
    const mnemonic = m[1].toLowerCase();
    const rest = m[2] || '';
    const operands = [];
    let cur = '';
    let depth = 0;
    for (const ch of rest) {
        if ('[{('.includes(ch)) depth++;
        if (']})'.includes(ch)) depth--;
        if (ch === ',' && depth === 0) {
            operands.push(cur.trim());
            cur = '';
        } else {
            cur += ch;
        }
    }
    if (cur.trim()) operands.push(cur.trim());
    return { mnemonic, operands };
}

function parseFloatImm(op) {
    const s = String(op ?? '').trim().replace(/^#/,'');
    if (!/^[-+]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?$/.test(s)) return null;
    const n = Number(s);
    return Number.isFinite(n) ? n : null;
}

function parseAsmImm(op) {
    const s = String(op ?? '').trim().replace(/^#/,'');
    if (!/^[-+]?(?:0x[0-9a-f]+|\d+)$/i.test(s)) return null;
    const n = Number(s.replace(/^[-+]/, ''));
    return s[0] === '-' ? -n : n;
}

function parseAsmImmBig(op) {
    const s = String(op ?? '').trim().replace(/^#/,'');
    if (!/^[-+]?(?:0x[0-9a-f]+|\d+)$/i.test(s)) return null;
    const neg = s[0] === '-';
    const b = BigInt(s.replace(/^[-+]/, ''));
    return neg ? -b : b;
}

function parseShiftOperand(operands, index) {
    const first = String(operands[index] ?? '').trim();
    if (!first) return null;
    const shift = operands[index + 1];
    if (!shift) return { operand: first, next: index + 1 };
    const m = /^([a-z]+)\s*#?(-?\d+)$/i.exec(String(shift).trim());
    if (!m) return { operand: first, next: index + 1 };
    return { operand: first, shift: m[1].toLowerCase(), amount: Number(m[2]), next: index + 2 };
}

function combineShiftedOperand(operands, index) {
    const p = parseShiftOperand(operands, index);
    if (!p) return '';
    if (!p.shift) return p.operand;
    return `${p.operand}, ${p.shift} #${p.amount}`;
}

function parseMem(op) {
    const s = String(op ?? '').trim();
    let m = /^\[([^\],]+)(?:,\s*([^\]]+))?\](!)?(?:,\s*(#?[+-]?(?:0x[0-9a-f]+|\d+)))?$/i.exec(s);
    if (!m) return null;
    const base = regNorm(m[1]);
    const body = m[2] == null ? null : m[2].trim();
    const writeback = !!m[3];
    const postIndex = m[4] != null ? parseAsmImm(m[4]) : null;
    const out = { base, offset: 0, offsetReg: null, extend: null, shift: 0, writeback, postIndex };
    if (!body) return out;
    const imm = parseAsmImm(body);
    if (imm != null) { out.offset = imm; return out; }
    const parts = body.split(',').map(x => x.trim());
    const reg = parts[0].toLowerCase();
    if (!isRegister(reg) || isSP(reg)) return null;
    out.offsetReg = reg;
    if (parts[1]) {
        const sm = /^(lsl|uxtw|sxtw|sxtx)(?:\s*#?(\d+))?$/i.exec(parts[1]);
        if (sm) {
            out.extend = sm[1].toLowerCase();
            out.shift = sm[2] ? Number(sm[2]) : 0;
        }
    }
    return out;
}

class Bytes extends Uint8Array {
    static wrap(x) {
        if (x instanceof Bytes) return x;
        if (x instanceof ArrayBuffer) return new Bytes(x);
        if (ArrayBuffer.isView(x)) return new Bytes(x.buffer, x.byteOffset, x.byteLength);
        throw new TypeError('bytes must be a Uint8Array or ArrayBuffer');
    }
    static copy(x) { const b = new Bytes(x.length); b.set(x); return b; }
    get view() { return this._v || (this._v = new DataView(this.buffer, this.byteOffset, this.byteLength)); }
    readUInt8(o) { return this.view.getUint8(o); }
    readInt8(o) { return this.view.getInt8(o); }
    readUInt16LE(o) { return this.view.getUint16(o, true); }
    readInt16LE(o) { return this.view.getInt16(o, true); }
    readUInt32LE(o) { return this.view.getUint32(o, true); }
    readInt32LE(o) { return this.view.getInt32(o, true); }
    readBigUInt64LE(o) { return this.view.getBigUint64(o, true); }
    readBigInt64LE(o) { return this.view.getBigInt64(o, true); }
    indexOf(value, from = 0) { return Uint8Array.prototype.indexOf.call(this, value, from); }
    toString(enc = 'utf8', start = 0, end = this.length) {
        const part = this.subarray(start, end);
        if (enc === 'ascii') { let t = ''; for (const b of part) t += String.fromCharCode(b & 0x7f); return t; }
        return new TextDecoder('utf-8').decode(part);
    }
}

function readU64(buf, off) {
    return Number(buf.readBigUInt64LE(off));
}

function readCString(buf, off) {
    if (off < 0 || off >= buf.length) return '';
    let end = off;
    while (end < buf.length && buf[end] !== 0) end++;
    return buf.toString('utf8', off, end);
}

function parseRaw(buf, base) {
    if (buf.length % 4 !== 0) throw new Error(`raw AArch64 code size must be a multiple of 4 bytes: ${buf.length}`);
    return {
        kind: 'raw',
        buffer: buf,
        text: { addr: base, offset: 0, size: buf.length, index: -1, name: '.text' },
        textBytes: buf,
        symbols: [],
        functionSymbols: [],
        relocations: new Map(),
        imageBase: base,
        entry: base,
    };
}

const MH_MAGIC_64 = 0xfeedfacf;
const CPU_TYPE_ARM64 = 0x0100000c;
const LC_SEGMENT_64 = 0x19;
const LC_SYMTAB = 0x2;
const LC_FUNCTION_STARTS = 0x26;
const N_SECT = 0x0e;
const N_EXT = 0x01;
const ARM64_RELOC_BRANCH26 = 2;
const R_AARCH64_JUMP26 = 282;
const R_AARCH64_CALL26 = 283;
const R_AARCH64_ADR_GOT_PAGE = 311;
const R_AARCH64_LD64_GOT_LO12_NC = 312;

function cStringFixed(buf, off, len) {
    let end=off;
    while(end<off+len && buf[end]!==0) end++;
    return buf.toString('ascii',off,end);
}

function uleb128(buf, off, end) {
    let value=0, shift=0, p=off;
    while(p<end) {
        const b=buf[p++]; value += (b & 0x7f) * 2**shift;
        if(!(b & 0x80)) return {value,offset:p};
        shift += 7;
        if(shift>56) break;
    }
    return null;
}

function uleb128Big(buf, off, end) {
    let value=0n, shift=0n, p=off;
    while(p<end) {
        const b=buf[p++]; value |= BigInt(b & 0x7f) << shift;
        if(!(b & 0x80)) return {value,offset:p};
        shift += 7n;
        if(shift>70n) break;
    }
    return null;
}

function machoName(name) {
    if (!name) return name;

    if (/^_OBJC_/.test(name)) return name;

    if (/^__Z/.test(name)) return name.slice(1);

    return name.startsWith('_') ? name.slice(1) : name;
}

function sliceFat(buf, arch = 'arm64') {
    if(buf.length<8) return null;
    const magic=buf.view.getUint32(0,false);
    if(magic!==0xcafebabe && magic!==0xcafebabf) return null;
    const wide=magic===0xcafebabf, n=buf.view.getUint32(4,false), stride=wide?32:20;
    let best=null;
    for(let i=0;i<n && 8+(i+1)*stride<=buf.length;i++) {
        const o=8+i*stride, cputype=buf.view.getUint32(o,false), subtype=buf.view.getUint32(o+4,false)&0xffffff;
        const off=wide ? Number(buf.view.getBigUint64(o+8,false)) : buf.view.getUint32(o+8,false);
        const size=wide ? Number(buf.view.getBigUint64(o+16,false)) : buf.view.getUint32(o+12,false);
        if(cputype!==CPU_TYPE_ARM64) continue;
        const isE = (subtype & 0xff) === 2;
        const better = arch === 'arm64e' ? (isE && !(best && best.isE)) : (!isE && !(best && !best.isE));
        if(!best || better) best={off,size,subtype,isE};
    }
    if(!best) throw new Error('universal binary has no arm64 slice');
    return buf.subarray(best.off,best.off+best.size);
}

const LC_DYLD_CHAINED_FIXUPS = 0x80000034;

function parseChainedFixups(buf, segments, dataoff, datasize) {
    const rebases=new Map(), binds=new Map();
    if(!dataoff || datasize<28 || dataoff+datasize>buf.length) return {rebases,binds};
    const hdr=dataoff;
    const startsOff=buf.readUInt32LE(hdr+4), importsOff=buf.readUInt32LE(hdr+8), symbolsOff=buf.readUInt32LE(hdr+12);
    const importsCount=buf.readUInt32LE(hdr+16), importsFormat=buf.readUInt32LE(hdr+20);
    const textSeg=segments.find(sg=>sg.name==='__TEXT');
    const imageBase=textSeg ? textSeg.vmaddr : 0;
    const imports=[];
    const cstr=o=>{ let q=o; while(q<buf.length && buf[q]) q++; return buf.toString('utf8',o,q); };
    for(let i=0;i<importsCount;i++) {
        let libOrd=0, nameOff=0, addend=0, weak=0;
        if(importsFormat===1 || importsFormat===2) {
            const stride=importsFormat===1?4:8, o=hdr+importsOff+i*stride;
            if(o+stride>buf.length) break;
            const w=buf.readUInt32LE(o);
            libOrd=w&0xff; weak=(w>>>8)&1; nameOff=w>>>9;
            if(importsFormat===2) addend=buf.readInt32LE(o+4);
        } else if(importsFormat===3) {
            const o=hdr+importsOff+i*16;
            if(o+16>buf.length) break;
            const lo=buf.readBigUInt64LE(o);
            libOrd=Number(lo&0xffffn); weak=Number((lo>>16n)&1n); nameOff=Number(lo>>32n);
            addend=Number(buf.readBigInt64LE(o+8));
        } else break;
        const raw=cstr(hdr+symbolsOff+nameOff);
        imports.push({rawName:raw,libOrd,weak,addend});
    }
    const segCount=buf.readUInt32LE(hdr+startsOff);
    for(let si=0; si<segCount && si<segments.length; si++) {
        const so=buf.readUInt32LE(hdr+startsOff+4+si*4);
        if(!so) continue;
        const sp=hdr+startsOff+so;
        if(sp+22>buf.length) continue;
        const pageSize=buf.readUInt16LE(sp+4), fmt=buf.readUInt16LE(sp+6), pageCount=buf.readUInt16LE(sp+20);
        const seg=segments[si];
        const arm64e=[1,7,9,10,12].includes(fmt), ptr64=[2,6,8].includes(fmt);
        if(!arm64e && !ptr64) continue;
        const stride=arm64e ? 8 : 4;
        const pageStarts=[];
        for(let i=0;i<pageCount;i++) pageStarts.push(buf.readUInt16LE(sp+22+i*2));
        const walk=(pageIdx,startOff)=>{
            let off=seg.fileoff+pageIdx*pageSize+startOff, vm=seg.vmaddr+pageIdx*pageSize+startOff;
            for(let guard=0; guard<(1<<22); guard++) {
                if(off+8>buf.length) break;
                const raw=buf.readBigUInt64LE(off);
                let next, isBind, ordinal=0, addend=0, target=0;
                if(ptr64) {
                    isBind=((raw>>63n)&1n)===1n; next=Number((raw>>51n)&0xfffn);
                    if(isBind) { ordinal=Number(raw&0xffffffn); addend=Number((raw>>24n)&0xffn); }
                    else { target=Number(raw&0xfffffffffn); if(fmt===6) target+=imageBase; }
                } else {
                    const auth=((raw>>63n)&1n)===1n;
                    isBind=((raw>>62n)&1n)===1n; next=Number((raw>>51n)&0x7ffn);
                    if(isBind) {
                        ordinal=Number(raw&(fmt===12?0xffffffn:0xffffn));
                        if(!auth) { addend=Number((raw>>32n)&0x7ffffn); if(addend&0x40000) addend-=0x80000; }
                    } else {
                        target=auth ? Number(raw&0xffffffffn) : Number(raw&0x7ffffffffffn);
                        if(fmt!==1 && fmt!==7) target+=imageBase;
                    }
                }
                if(isBind) {
                    const imp=imports[ordinal];
                    if(imp) binds.set(vm,{symbol:machoName(imp.rawName),rawSymbol:imp.rawName,type:1,dylib:imp.libOrd,addend:imp.addend+addend,chained:true});
                } else rebases.set(vm,target);
                if(!next) break;
                off+=next*stride; vm+=next*stride;
            }
        };
        for(let pi=0; pi<pageCount; pi++) {
            const ps=pageStarts[pi];
            if(ps===0xffff) continue;
            if(ps&0x8000) {
                for(let k=ps&0x7fff; k<pageStarts.length; k++) { const e=pageStarts[k]; walk(pi,e&0x7fff); if(e&0x8000) break; }
            } else walk(pi,ps);
        }
    }
    return {rebases,binds};
}

function parseMachO64(buf) {
    if(buf.length<32) return null;
    const magic=buf.readUInt32LE(0);
    if(magic!==MH_MAGIC_64) return null;
    const cputype=buf.readUInt32LE(4);
    if(cputype!==CPU_TYPE_ARM64) throw new Error(`Mach-O CPU type ${hex(cputype)} is not arm64`);
    const filetype=buf.readUInt32LE(12);
    const ncmds=buf.readUInt32LE(16), sizeofcmds=buf.readUInt32LE(20);
    if(32+sizeofcmds>buf.length) throw new Error('truncated Mach-O load commands');

    const sections=[];
    const segments=[];
    let symtab=null, dysymtab=null, functionStarts=null, dyldInfo=null, entryoff=null, chainedFixups=null;
    let p=32;
    for(let i=0;i<ncmds;i++) {
        if(p+8>buf.length) throw new Error('truncated Mach-O load command');
        const cmd=buf.readUInt32LE(p), cmdsize=buf.readUInt32LE(p+4);
        if(cmdsize<8 || p+cmdsize>buf.length) throw new Error('invalid Mach-O load command size');
        if(cmd===LC_SEGMENT_64) {
            if(cmdsize<72) throw new Error('invalid LC_SEGMENT_64');
            const segname=cStringFixed(buf,p+8,16);
            const vmaddr=readU64(buf,p+24), vmsize=readU64(buf,p+32), fileoff=readU64(buf,p+40), filesize=readU64(buf,p+48);
            segments.push({index:segments.length,name:segname,vmaddr,vmsize,fileoff,filesize});
            const nsects=buf.readUInt32LE(p+64);
            let q=p+72;
            for(let j=0;j<nsects;j++) {
                if(q+80>p+cmdsize) throw new Error('truncated Mach-O section table');
                const sectname=cStringFixed(buf,q,16), secSeg=cStringFixed(buf,q+16,16);
                const addr=readU64(buf,q+32), size=readU64(buf,q+40), offset=buf.readUInt32LE(q+48);
                const align=buf.readUInt32LE(q+52), reloff=buf.readUInt32LE(q+56), nreloc=buf.readUInt32LE(q+60);
                const flags=buf.readUInt32LE(q+64), reserved1=buf.readUInt32LE(q+68), reserved2=buf.readUInt32LE(q+72), reserved3=buf.readUInt32LE(q+76);
                sections.push({index:sections.length+1,segment:secSeg,name:`${secSeg},${sectname}`,sectname,segname:secSeg,addr,size,offset,align,reloff,nreloc,flags,reserved1,reserved2,reserved3});
                q+=80;
            }
        } else if(cmd===LC_SYMTAB) {
            if(cmdsize>=24) symtab={symoff:buf.readUInt32LE(p+8),nsyms:buf.readUInt32LE(p+12),stroff:buf.readUInt32LE(p+16),strsize:buf.readUInt32LE(p+20)};
        } else if(cmd===0x0b) {
            if(cmdsize>=80) dysymtab={
                ilocalsym:buf.readUInt32LE(p+8),nlocalsym:buf.readUInt32LE(p+12),
                iextdefsym:buf.readUInt32LE(p+16),nextdefsym:buf.readUInt32LE(p+20),
                iundefsym:buf.readUInt32LE(p+24),nundefsym:buf.readUInt32LE(p+28),
                indirectsymoff:buf.readUInt32LE(p+56),nindirectsyms:buf.readUInt32LE(p+60),
            };
        } else if(cmd===0x22 || cmd===0x80000022) {
            if(cmdsize>=48) dyldInfo={
                rebaseOff:buf.readUInt32LE(p+8),rebaseSize:buf.readUInt32LE(p+12),
                bindOff:buf.readUInt32LE(p+16),bindSize:buf.readUInt32LE(p+20),
                weakBindOff:buf.readUInt32LE(p+24),weakBindSize:buf.readUInt32LE(p+28),
                lazyBindOff:buf.readUInt32LE(p+32),lazyBindSize:buf.readUInt32LE(p+36),
                exportOff:buf.readUInt32LE(p+40),exportSize:buf.readUInt32LE(p+44),
            };
        } else if(cmd===LC_DYLD_CHAINED_FIXUPS) {
            if(cmdsize>=16) chainedFixups={dataoff:buf.readUInt32LE(p+8),datasize:buf.readUInt32LE(p+12)};
        } else if(cmd===LC_FUNCTION_STARTS) {
            if(cmdsize>=16) functionStarts={dataoff:buf.readUInt32LE(p+8),datasize:buf.readUInt32LE(p+12)};
        } else if(cmd===0x80000028 && cmdsize>=24) {
            entryoff=readU64(buf,p+8);
        }
        p+=cmdsize;
    }

    const text=sections.find(s=>s.segname==='__TEXT' && s.sectname==='__text');
    if(!text) throw new Error('Mach-O has no __TEXT,__text section');
    if(text.offset+text.size>buf.length) throw new Error('truncated Mach-O __text');

    const strbuf=symtab && symtab.stroff+symtab.strsize<=buf.length ? buf.subarray(symtab.stroff,symtab.stroff+symtab.strsize) : new Bytes(0);
    const symbols=[];
    if(symtab) {
        for(let i=0;i<symtab.nsyms;i++) {
            const o=symtab.symoff+i*16;
            if(o+16>buf.length) break;
            const nStrx=buf.readUInt32LE(o), nType=buf[o+4], nSect=buf[o+5], nDesc=buf.readUInt16LE(o+6), nValue=readU64(buf,o+8);
            const rawName=readCString(strbuf,nStrx);
            symbols.push({index:i,name:machoName(rawName),rawName,bind:(nType&N_EXT)?1:0,type:nType&0x0e,other:0,desc:nDesc,shndx:nSect,value:nValue,size:0});
        }
    }

    const dataSymbols=symbols
        .filter(s=>s.type===N_SECT && s.shndx!==text.index && s.shndx>0 && s.name && !/^(?:l_|ltmp|L)/.test(s.name) && s.value && !(s.desc & 0x8))
        .map(s=>({name:s.name,value:s.value,size:0}))
        .sort((a,b)=>a.value-b.value);
    const functionCandidates=symbols.filter(s=>s.type===N_SECT && s.shndx===text.index && s.name && s.name!=='ltmp0' && !/^ltmp\d+$/i.test(s.name));
    functionCandidates.sort((a,b)=>a.value-b.value || b.bind-a.bind || a.name.localeCompare(b.name));
    const functionSymbols=[];
    const seenFn=new Set();
    for(const s of functionCandidates) {
        if(seenFn.has(s.value)) continue;
        seenFn.add(s.value);
        functionSymbols.push(s);
    }

    if(functionStarts && functionStarts.dataoff+functionStarts.datasize<=buf.length) {
        let off=functionStarts.dataoff, end=off+functionStarts.datasize, addr=0, index=0;
        while(off<end) {
            const u=uleb128(buf,off,end); if(!u) break; off=u.offset;
            if(u.value===0) break;
            addr += u.value;
            if(addr<text.addr || addr>=text.addr+text.size || (addr & 3)) continue;
            if(!seenFn.has(addr)) {
                seenFn.add(addr);
                functionSymbols.push({index:-(++index),name:`sub_${addr.toString(16)}`,bind:0,type:N_SECT,shndx:text.index,value:addr,size:0,synthetic:true});
            }
        }
        functionSymbols.sort((a,b)=>a.value-b.value || b.bind-a.bind || a.name.localeCompare(b.name));
    }

    const relocations=new Map();
    if(text.reloff && text.nreloc) {
        for(let i=0;i<text.nreloc;i++) {
            const o=text.reloff+i*8;
            if(o+8>buf.length) break;
            const rAddress=buf.readInt32LE(o), word=buf.readUInt32LE(o+4);
            if(rAddress<0) continue;
            const symbolnum=word & 0x00ffffff, pcrel=(word>>>24)&1, length=(word>>>25)&3, external=(word>>>27)&1, rType=(word>>>28)&0xf;
            if(rType===10) continue;
            const sym=external ? symbols[symbolnum] : null;
            const address=text.addr+rAddress;
            relocations.set(address,{offset:rAddress,type:rType,format:'macho',symbol:sym?.name||'',symIndex:symbolnum,pcrel,length,external});
        }
    }

    const indirectSymbols=[];
    if(dysymtab && dysymtab.indirectsymoff+dysymtab.nindirectsyms*4<=buf.length) {
        for(let i=0;i<dysymtab.nindirectsyms;i++) indirectSymbols.push(buf.readUInt32LE(dysymtab.indirectsymoff+i*4));
    }

    const indirectByAddress=new Map();
    for(const sec of sections) {
        const secType=sec.flags & 0xff;
        const isStub=secType===0x8 && sec.reserved2>0;
        const isIndirectPtr=[0x6,0x7,0x10].includes(secType);
        if(!isStub && !isIndirectPtr) continue;
        const stride=isStub ? sec.reserved2 : 8;
        const count=Math.floor(sec.size/stride);
        for(let i=0;i<count;i++) {
            const idx=indirectSymbols[sec.reserved1+i];
            const sym=symbols[idx];
            if(sym?.name) indirectByAddress.set(sec.addr+i*stride,{name:machoName(sym.rawName||sym.name),symbolIndex:idx,section:sec.name});
        }
    }

    function readSlebAt(off,end) {
        let value=0, shift=0, p=off, byte=0;
        while(p<end) { byte=buf[p++]; value += (byte&0x7f)*2**shift; shift+=7; if(!(byte&0x80)){ if(shift<53 && (byte&0x40)) value -= 2**shift; return {value,offset:p}; } }
        return null;
    }
    const binds=new Map();
    const parseBindStream=(dataoff,datasize,lazy=false)=>{
        if(!dataoff || !datasize || dataoff+datasize>buf.length) return;
        const end=dataoff+datasize; let p=dataoff, segmentIndex=-1, address=0, symbol='', type=1, dylib=0, addend=0;
        const doBind=()=>{ if(symbol && segmentIndex>=0) binds.set(address,{symbol:machoName(symbol),rawSymbol:symbol,type,dylib,addend}); };
        while(p<end) {
            const byte=buf[p++], imm=byte&0xf0, arg=byte&0x0f;
            if(byte===0x00) { if(lazy) continue; break; }
            if(imm===0x10) { dylib=arg; continue; }
            if(imm===0x20) { const u=uleb128(buf,p,end); if(!u) break; dylib=u.value; p=u.offset; continue; }
            if(imm===0x30) { dylib=arg===0 ? 0 : (arg | 0xf0); continue; }
            if(imm===0x40) { let q=p; while(q<end && buf[q]) q++; symbol=buf.toString('utf8',p,q); p=Math.min(q+1,end); continue; }
            if(imm===0x50) { type=arg; continue; }
            if(imm===0x60) { const sl=readSlebAt(p,end); if(!sl) break; addend=sl.value; p=sl.offset; continue; }
            if(imm===0x70) { const u=uleb128(buf,p,end); if(!u) break; segmentIndex=arg; p=u.offset; const seg=segments?.[segmentIndex]; address=seg?seg.vmaddr+u.value:u.value; continue; }
            if(imm===0x80) { const u=uleb128Big(buf,p,end); if(!u) break; p=u.offset; address=Number(BigInt.asUintN(64,BigInt(address)+u.value)); continue; }
            if(imm===0x90) { doBind(); address+=8; continue; }
            if(imm===0xa0) { const u=uleb128Big(buf,p,end); if(!u) break; p=u.offset; address=Number(BigInt.asUintN(64,BigInt(address)+8n+u.value)); continue; }
            if(imm===0xb0) { doBind(); address+=8*(arg+1); continue; }
            if(imm===0xc0) { const u1=uleb128(buf,p,end); if(!u1) break; p=u1.offset; const u2=uleb128Big(buf,p,end); if(!u2) break; p=u2.offset; for(let i=0;i<u1.value;i++){doBind();address=Number(BigInt.asUintN(64,BigInt(address)+8n+u2.value));} continue; }
            if(imm===0xd0) {

                if(arg===0) { const u=uleb128(buf,p,end); if(!u) break; p=u.offset; }
                else if(arg===1) { doBind(); address+=8; }
                continue;
            }
        }
    };
    if(dyldInfo) { parseBindStream(dyldInfo.bindOff,dyldInfo.bindSize); parseBindStream(dyldInfo.lazyBindOff,dyldInfo.lazyBindSize,true); }
    let rebases=new Map();
    if(chainedFixups) {
        const cf=parseChainedFixups(buf,segments,chainedFixups.dataoff,chainedFixups.datasize);
        rebases=cf.rebases;
        for(const [a,b] of cf.binds) binds.set(a,b);
    }

    return {
        kind:'macho',filetype,cpuSubtype:buf.readUInt32LE(8),entry:entryoff,buffer:buf,sections,segments,text,textBytes:Bytes.copy(buf.subarray(text.offset,text.offset+text.size)),symbols,functionSymbols,relocations,imageBase:text.addr,indirectSymbols,indirectByAddress,binds,rebases,segmentsList:segments,dysymtab,dyldInfo,chainedFixups,
    };
}

class BinaryImage {
    constructor(bytes, base = 0, opts = {}) {
        this.buffer = Bytes.wrap(bytes);
        this.buffer = sliceFat(this.buffer, opts.arch) || this.buffer;
        this.elf = parseELF64(this.buffer);
        this.macho = this.elf ? null : parseMachO64(this.buffer);
        this.meta = this.elf || this.macho || parseRaw(this.buffer, base);
        this.functions = new Map();
        this.inferredNames = [];
        if(opts.tableNames !== false) this.inferNamesFromTables();
    }

    isCodeSection(sec) {
        if(this.meta.kind==='macho') return (sec.flags & 0x80000400)!==0 || sec.sectname==='__text' || sec.sectname==='__stubs';
        if(this.meta.kind==='elf') return (sec.flags & 0x4)!==0;
        return false;
    }

    renameFunctionSymbol(sym, name, source) {
        const taken=new Set(this.meta.functionSymbols.map(x=>x.name));
        let n=String(name).replace(/[^A-Za-z0-9_$.]/g,'_'); if(/^[0-9]/.test(n)) n='_'+n;
        let final=n, k=2; while(taken.has(final)) final=`${n}_${k++}`;
        this.inferredNames.push({address:sym.value,from:sym.name,name:final,source});
        sym.name=final; sym.inferred=source; this._fnByValue=null; this._symByValue=null; this._sortedFn=null;
    }

    inferNamesFromTables() {
        const meta=this.meta;
        if(meta.kind==='raw' || !meta.sections) return;
        const targets=new Map();
        for(const sym of meta.functionSymbols) if(sym.synthetic || /^sub_[0-9a-f]+$/.test(sym.name)) targets.set(sym.value,sym);
        if(!targets.size) return;
        const textStart=this.getTextStart(), textEnd=this.getTextEnd(), buf=meta.buffer;
        const identLike=t=>typeof t==='string' && t.length>=2 && t.length<=200 && /^[A-Za-z_][A-Za-z0-9_$.:]*$/.test(t);
        const nameAt=(a,kind)=>{
            const sec=this.sectionContaining(a); if(!sec || a+(kind==='abs'?8:4)>sec.addr+sec.size) return null;
            let t;
            if(kind==='abs') { const r=meta.rebases?.get(a); t = r!=null ? r : (meta.chainedFixups ? null : Number(buf.readBigUInt64LE(sec.offset+(a-sec.addr)))); }
            else t = a + buf.readInt32LE(sec.offset+(a-sec.addr));
            if(t==null) return null;
            const tg=this.addressTarget(t);
            return tg && (tg.kind==='string'||tg.kind==='selector') && identLike(tg.value) ? tg.value : null;
        };
        const hits=[];
        for(const sec of meta.sections) {
            if(!sec.addr || sec.size<4 || this.isCodeSection(sec) || this.isZeroFillSection(sec) || this.isStringSection(sec)) continue;
            if(/unwind|eh_frame|except|debug|cfstring|init_offsets|got|symbol_ptr/i.test(sec.sectname||sec.name||'')) continue;
            for(let o=0;o+4<=sec.size;o+=4) {
                const a=sec.addr+o;
                if((o&7)===0 && o+8<=sec.size) {
                    const r=meta.rebases?.get(a);
                    const t = r!=null ? r : (meta.chainedFixups ? null : Number(buf.readBigUInt64LE(sec.offset+o)));
                    if(t!=null && targets.has(t)) hits.push({a,kind:'abs',target:t,sec});
                }
                const rel=buf.readInt32LE(sec.offset+o);
                if(rel!==0 && targets.has(a+rel) && a+rel>=textStart && a+rel<textEnd) hits.push({a,kind:'rel',target:a+rel,sec});
            }
        }
        const named=new Map();
        for(let i=0;i<hits.length;) {
            let j=i+1;
            const stride = (j<hits.length && hits[j].kind===hits[i].kind && hits[j].sec===hits[i].sec) ? hits[j].a-hits[i].a : 0;
            if(stride>=4 && stride<=64) { while(j+1<hits.length && hits[j+1].kind===hits[i].kind && hits[j+1].sec===hits[i].sec && hits[j+1].a-hits[j].a===stride) j++; j++; } else j=i+1;
            const run=hits.slice(i,j), kind=run[0].kind, step=kind==='abs'?8:4;
            if(run.length>=2) {
                let best=null;
                for(let r=-(stride-4); r<stride; r+=4) {
                    if(r===0 || (kind==='abs' && (r%8)!==0)) continue;
                    const names=run.map(h=>nameAt(h.a+r,kind));
                    const count=names.filter(Boolean).length;
                    if(count>=Math.ceil(run.length/2) && (!best || count>best.count || (count===best.count && Math.abs(r)<Math.abs(best.r)))) best={r,count,names};
                }
                if(best) run.forEach((h,k)=>{ if(best.names[k] && !named.has(h.target)) named.set(h.target,best.names[k]); });
            } else {
                const h=run[0], found=[];
                for(let r=-12;r<=12;r+=4) { if(r===0 || (kind==='abs' && (r%8)!==0)) continue; const t=nameAt(h.a+r,kind); if(t) found.push(t); }
                if(found.length===1 && !named.has(h.target)) named.set(h.target,found[0]);
            }
            i=j;
        }
        for(const [addr,name] of named) this.renameFunctionSymbol(targets.get(addr),name,'data-table');
    }

    getTextStart() { return this.meta.text.addr; }
    getTextEnd() { return this.meta.text.addr + this.meta.text.size; }

    allWords(decoder) {
        const bytes = this.meta.textBytes;
        if (bytes.length % 4 !== 0) throw new Error('text section size is not multiple of 4');
        const out = [];
        for (let off = 0; off < bytes.length; off += 4) {
            const address = this.meta.text.addr + off;
            const word = bytes.readUInt32LE(off);
            const asm = decoder.decodeArm64Unchecked(word >>> 0);
            const parts = normalizePAC(splitInstruction(asm));
            const relocation = this.meta.relocations.get(address) || null;
            out.push({
                fileOffset: this.meta.text.offset + off,
                textOffset: off,
                address,
                word: word >>> 0,
                asm,
                mnemonic: parts.mnemonic,
                operands: parts.operands,
                unknown: typeof asm !== 'string' || /^Unknown/i.test(asm),
                relocation,
            });
        }
        return out;
    }

    getFunctionSymbols() { return this.meta.functionSymbols.slice(); }

    functionNameAt(address) {
        if (!this._fnByValue) {
            this._fnByValue = new Map();
            for (const s of this.meta.functionSymbols) if (!this._fnByValue.has(s.value)) this._fnByValue.set(s.value, s);
        }
        return this._fnByValue.get(address)?.name ?? null;
    }

    codeSymbolAt(address) {
        const direct = this.functionNameAt(address);
        if (direct) return direct;
        const indirect = this.meta.indirectByAddress?.get(address);
        return indirect ? indirect.name : null;
    }

    dataBindAt(address) {
        const b = this.meta.binds?.get(address);
        if (b?.symbol) return b.symbol;
        const indirect = this.meta.indirectByAddress?.get(address);
        return indirect?.name || null;
    }

    dataSymbolAt(address) {
        const list=this.meta.dataSymbols;
        if(!list || !list.length) return null;
        let lo=0, hi=list.length-1, best=null;
        while(lo<=hi) { const mid=(lo+hi)>>1; if(list[mid].value<=address) { best=list[mid]; lo=mid+1; } else hi=mid-1; }
        if(!best) return null;
        if(best.value===address) return best.name;
        return best.size && address<best.value+best.size ? best.name : null;
    }

    globalAddressName(address) {
        const sec=this.sectionContaining(address);
        if(!sec || this.isCodeSection(sec)) return null;
        const sym=this.dataSymbolAt(address);
        if(this.meta.kind==='macho') {
            const special = new Set(['__got','__la_symbol_ptr','__objc_selrefs','__objc_classrefs','__objc_superrefs','__objc_protorefs','__cfstring']);
            if(!sec.segname || sec.segname==='__TEXT' || special.has(sec.sectname) || [0x6,0x7,0x10].includes(sec.flags & 0xff)) return null;
            return sym || `global_${address.toString(16)}`;
        }
        if(this.meta.kind==='elf') {
            if((sec.flags & 0x1)===0 || this.isStringSection(sec)) return null;
            return sym || `global_${address.toString(16)}`;
        }
        return null;
    }

    sectionsBySect(sectname) {
        return (this.meta.sections||[]).filter(sec=>sec.sectname===sectname);
    }

    sectionContaining(address) {
        return (this.meta.sections||[]).find(sec=>address>=sec.addr && address<sec.addr+sec.size) || null;
    }

    isZeroFillSection(sec) {
        if(this.meta.kind==='macho') return [0x1,0xc,0x12].includes(sec.flags & 0xff);
        return sec.type===8;
    }

    vmToFile(address, size=1) {
        for(const seg of this.meta.segments||[]) {
            const backed=Math.min(seg.vmsize,seg.filesize);
            if(address>=seg.vmaddr && address+size<=seg.vmaddr+backed) return seg.fileoff+(address-seg.vmaddr);
        }
        for(const sec of this.meta.sections||[]) {
            if(!sec.addr || this.isZeroFillSection(sec)) continue;
            if(address>=sec.addr && address+size<=sec.addr+sec.size) return sec.offset+(address-sec.addr);
        }
        return null;
    }

    isStringSection(sec) {
        if(!sec || this.isZeroFillSection(sec)) return false;
        if(this.meta.kind==='macho') return (sec.flags & 0xff)===0x2 || sec.sectname==='__ustring';
        if(this.meta.kind==='elf') return (sec.flags & 0x20)!==0;
        return false;
    }

    strings() {
        if(this._strings) return this._strings;
        const out=[], buf=this.meta.buffer;
        for(const sec of this.meta.sections||[]) {
            if(!this.isStringSection(sec) || !sec.addr) continue;
            const off=sec.offset, end=Math.min(off+sec.size,buf.length);
            const label=sec.sectname||sec.name;
            if(sec.sectname==='__ustring') {
                let start=off;
                for(let i=off;i+2<=end;i+=2) {
                    if(buf.readUInt16LE(i)===0) {
                        if(i>start) { let t=''; for(let j=start;j<i;j+=2) t+=String.fromCharCode(buf.readUInt16LE(j)); out.push({address:sec.addr+(start-off),section:label,text:t}); }
                        start=i+2;
                    }
                }
                continue;
            }
            let start=off;
            for(let i=off;i<=end;i++) {
                if(i===end || buf[i]===0) {
                    if(i>start) out.push({address:sec.addr+(start-off),section:label,text:buf.toString('utf8',start,i)});
                    start=i+1;
                }
            }
        }
        return this._strings=out;
    }

    looksLikeText(text) {
        if(!text || text.length<3) return false;
        for(let i=0;i<text.length;i++) { const c=text.charCodeAt(i); if(c<9 || (c>13 && c<32) || c===127 || c===0xfffd) return false; }
        return true;
    }

    readVM(address, size) {
        const off=this.vmToFile(address,size);
        if(off==null || off+size>this.meta.buffer.length) return null;
        return this.meta.buffer.subarray(off,off+size);
    }

    readonlyBitsAt(address, width) {
        const sec=this.sectionContaining(address);
        if(!sec || address+width/8>sec.addr+sec.size) return null;
        let ro=false;
        if(this.meta.kind==='macho') ro=['__const','__literal4','__literal8','__literal16'].includes(sec.sectname) || [0x3,0x4,0xe].includes(sec.flags & 0xff);
        else if(this.meta.kind==='elf') ro=/^\.rodata/.test(sec.name||'') && (sec.flags & 0x1)===0;
        if(!ro) return null;
        const b=this.readVM(address,width/8);
        if(!b) return null;
        return width===32 ? BigInt(b.readUInt32LE(0)) : width===64 ? b.readBigUInt64LE(0) : null;
    }

    cStringAt(address, maxLen=4096) {
        const off=this.vmToFile(address,1);
        if(off==null) return null;
        const buf=this.meta.buffer; let end=off;
        while(end<buf.length && end-off<maxLen && buf[end]) end++;
        return buf.toString('utf8',off,end);
    }

    utf16At(address, units=null) {
        const off=this.vmToFile(address,2);
        if(off==null) return null;
        const buf=this.meta.buffer; let out='';
        for(let o=off, n=0; o+2<=buf.length && (units==null || n<units) && n<4096; o+=2, n++) {
            const u=buf.readUInt16LE(o);
            if(u===0 && units==null) break;
            out+=String.fromCharCode(u);
        }
        return out;
    }

    pointerAt(address) {
        const bind=this.meta.binds?.get(address);
        if(bind) return {kind:'bind',symbol:bind.symbol,addend:bind.addend||0};
        const rb=this.meta.rebases?.get(address);
        if(rb!=null) return {kind:'ptr',value:rb};
        const b=this.readVM(address,8);
        if(!b) return null;
        return {kind:'ptr',value:Number(b.readBigUInt64LE(0))};
    }

    addressTarget(address) {

        for(const cf of this.sectionsBySect('__cfstring')) {
            if(address>=cf.addr && address+32<=cf.addr+cf.size && ((address-cf.addr)%32===0)) {
                const sp=this.pointerAt(address+16);
                const lenBytes=this.readVM(address+24,8);
                const len=lenBytes ? Number(lenBytes.readBigUInt64LE(0)) : null;
                if(sp?.kind==='ptr') {
                    const sec=this.sectionContaining(sp.value);
                    if(sec?.sectname==='__ustring') { const t=this.utf16At(sp.value,len); if(t!=null) return {kind:'cfstring',value:t,address}; }
                    const str=this.addressTarget(sp.value);
                    if(str?.kind==='string') return {kind:'cfstring',value:str.value,address};
                }
            }
        }

        if(this.meta.binds?.has(address)) return { kind:'symbol', name:this.meta.binds.get(address).symbol, address };
        const indirect = this.meta.indirectByAddress?.get(address);
        if (indirect?.name) return { kind:'symbol', name:indirect.name, address, indirect:true };

        const slotSections=new Set(['__objc_selrefs','__objc_classrefs','__objc_superrefs','__objc_protorefs','__objc_classlist']);
        const here=this.sectionContaining(address);
        if(here && slotSections.has(here.sectname) && address+8<=here.addr+here.size) {
            const ptr=this.pointerAt(address);
            if(ptr?.kind==='bind') return { kind:'symbol', name:ptr.symbol, address };
            if(ptr?.kind==='ptr' && ptr.value!==address) {
                const target=this.addressTarget(ptr.value);
                if(target) return target;
            }
        }

        if(here && this.isStringSection(here)) {
            if(here.sectname==='__ustring') {
                const text=this.utf16At(address);
                if(text!=null) return {kind:'string',value:text,address,section:here.sectname};
            }
            const text=this.cStringAt(address);
            if(text!=null) return {kind: here.sectname==='__objc_methname' ? 'selector' : 'string', value:text,address,section:here.sectname||here.name};
        }

        if(here && this.meta.kind==='elf' && /^\.rodata/.test(here.name||'')) {
            const text=this.cStringAt(address,Math.min(4096,here.addr+here.size-address));
            if(this.looksLikeText(text)) return {kind:'string',value:text,address,section:here.name};
        }
        if(here && !this.isCodeSection(here) && !this.isZeroFillSection(here)) {
            const ro = this.meta.kind==='macho' ? here.sectname==='__const'
                     : this.meta.kind==='elf' ? (/^\.rodata/.test(here.name||'') && (here.flags & 0x1)===0) : false;
            if(ro) return {kind:'rodata',name:`rodata_${address.toString(16)}`,address,section:here.sectname||here.name};
        }
        const fname=this.meta.kind!=='raw' && address>=this.getTextStart() && address<this.getTextEnd() ? this.functionNameAt(address) : null;
        if(fname) return { kind:'function', name:fname, address };
        const globalName=this.globalAddressName(address);
        if(globalName) return {kind:'global',name:globalName,address};
        return null;
    }

    symbolAt(address) {
        if (!this._symByValue) {
            this._symByValue = new Map();
            for (const x of this.meta.symbols) if (x.name && !this._symByValue.has(x.value)) this._symByValue.set(x.value, x);
        }
        const s = this._symByValue.get(address);
        return s ? s.name : this.dataBindAt(address);
    }

    sectionByName(name) {
        return this.meta.sections?.find(s => s.name === name) || null;
    }

    readSection(name, offset=0, size=null) {
        const sec=this.sectionByName(name);
        if(!sec) return null;
        const n=size==null ? sec.size-offset : size;
        if(offset<0 || n<0 || offset+n>sec.size) return null;
        return this.meta.buffer.subarray(sec.offset+offset,sec.offset+offset+n);
    }

    readSectionValue(name, offset, width, signed=false) {
        const b=this.readSection(name,offset,width/8);
        if(!b || b.length!==width/8) return null;
        if(width===8) return signed ? b.readInt8(0) : b.readUInt8(0);
        if(width===16) return signed ? b.readInt16LE(0) : b.readUInt16LE(0);
        if(width===32) return signed ? b.readInt32LE(0) : b.readUInt32LE(0);
        if(width===64) return signed ? Number(b.readBigInt64LE(0)) : Number(b.readBigUInt64LE(0));
        return null;
    }

    functionRange(start) {
        this.functionNameAt(-1);
        const s = this._fnByValue.get(start);
        if (s && s.size > 0) return [start, Math.min(start + s.size, this.getTextEnd())];
        const next = this.nextFunctionSymbol(start);
        return [start, next ? next.value : this.getTextEnd()];
    }

    nextFunctionSymbol(start) {
        if (!this._sortedFn) this._sortedFn = [...this.meta.functionSymbols].sort((a, b) => a.value - b.value);
        let lo = 0, hi = this._sortedFn.length;
        while (lo < hi) { const mid = (lo + hi) >> 1; if (this._sortedFn[mid].value > start) hi = mid; else lo = mid + 1; }
        return this._sortedFn[lo] || null;
    }
}

function isCondBranch(m) { return /^b\.(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|nv)$/.test(m); }

function directTarget(insn) {
    const imm = parseAsmImm(insn.operands[0]);
    if (imm == null || (insn.relocation && ((insn.relocation.format==='macho' && insn.relocation.type===ARM64_RELOC_BRANCH26) || insn.relocation.type === 282 || insn.relocation.type === 283))) return null;
    return insn.address + imm;
}

function branchInfo(insn) {
    const m = insn.mnemonic, o = insn.operands;
    if (m === 'b') return { kind: 'jump', target: directTarget(insn), symbol: insn.relocation?.symbol || null };
    if (isCondBranch(m)) return { kind: 'cond', condition: m.slice(2), target: directTarget(insn), source: m };
    if (m === 'cbz' || m === 'cbnz') {
        const off = parseAsmImm(o[1]);
        return off == null ? null : { kind: 'cond', condition: `${o[0]} ${m === 'cbnz' ? '!=' : '=='} 0`, target: insn.address + off, source: m };
    }
    if (m === 'tbz' || m === 'tbnz') {
        const off = parseAsmImm(o[2]);
        return off == null ? null : { kind: 'cond', condition: `${o[0]} bit ${parseAsmImm(o[1]) ?? o[1]} ${m === 'tbnz' ? '!= 0' : '== 0'}`, target: insn.address + off, source: m };
    }
    if (m === 'bl') return { kind: 'call', target: directTarget(insn), symbol: insn.relocation?.symbol || null };
    if (m === 'blr') return { kind: 'call-indirect', reg: o[0] || 'x0' };
    if (m === 'ret') {
        const r = canonicalReg(o[0] || 'x30');
        return r === 'x30' ? { kind: 'return', reg: r } : { kind: 'ret-indirect', reg: r };
    }
    if (m === 'retaa' || m === 'retab') return { kind: 'return', reg: 'x30' };
    if (m === 'br' || m === 'braa' || m === 'brab' || m === 'braaz' || m === 'brabz') {
        return { kind: 'indirect-jump', reg: o[0] || 'x0' };
    }
    if (m === 'eret' || m === 'drps' || m === 'hlt') return { kind: 'terminal' };
    return null;
}

function reachableInstructions(instructions, entry, end = Infinity, options = {}) {
    const byAddr = new Map(instructions.filter(i => i.address >= entry && i.address < end).map(i => [i.address, i]));
    if (!byAddr.has(entry)) return [];
    const out = new Map();
    const queue = [entry];
    const starts = new Set();
    while (queue.length) {
        const start = queue.shift();
        if (starts.has(start)) continue;
        starts.add(start);
        let pc = start;
        while (byAddr.has(pc)) {
            if (out.has(pc)) break;
            const insn = byAddr.get(pc);
            out.set(pc, insn);
            const b = branchInfo(insn);
            if (b?.kind === 'cond') {
                if (b.target != null && byAddr.has(b.target)) queue.push(b.target);
                if (byAddr.has(pc + 4)) queue.push(pc + 4);
                break;
            }
            if (b?.kind === 'jump') {
                const isBackwardTailcall = options.tailcallBeforeEntry && b.target != null && b.target < entry;
                if (!isBackwardTailcall && b.target != null && byAddr.has(b.target)) queue.push(b.target);

                if (options.linearAfterIndirect && byAddr.has(pc + 4)) queue.push(pc + 4);
                break;
            }
            if (b && ['return','terminal','ret-indirect','indirect-jump'].includes(b.kind)) {

                if (b.kind === 'indirect-jump' && options.linearAfterIndirect && byAddr.has(pc + 4)) {
                    queue.push(pc + 4);
                }
                break;
            }
            if (!byAddr.has(pc + 4)) break;
            pc += 4;
        }
    }
    return [...out.values()].sort((a,b) => a.address - b.address);
}

function buildCFG(instructions, entryAddress, options = {}) {
    const reachable = reachableInstructions(instructions, entryAddress, Infinity, {...options, tailcallBeforeEntry:true});
    const byAddr = new Map(reachable.map(i => [i.address, i]));
    if (!byAddr.has(entryAddress)) throw new Error(`entry ${hex64(entryAddress)} not in decoded region`);

    const leaders = new Set([entryAddress]);
    for (const insn of reachable) {
        const b = branchInfo(insn);
        if (b?.target != null && byAddr.has(b.target)) leaders.add(b.target);
        if (b?.kind === 'cond' && byAddr.has(insn.address + 4)) leaders.add(insn.address + 4);
        if (b && ['jump','cond','return','terminal','ret-indirect','indirect-jump'].includes(b.kind) && byAddr.has(insn.address + 4)) leaders.add(insn.address + 4);
    }

    const blocks = [];
    let current = null;
    for (const insn of reachable) {
        if (leaders.has(insn.address)) {
            current = { address: insn.address, instructions: [], successors: [], predecessors: [] };
            blocks.push(current);
        }
        if (!current) throw new Error('CFG builder lost current block');
        current.instructions.push(insn);
        const b = branchInfo(insn);
        if (b && ['jump','cond','return','terminal','ret-indirect','indirect-jump'].includes(b.kind)) current = null;
    }

    const blockByAddr = new Map(blocks.map(b => [b.address, b]));
    for (const block of blocks) {
        const last = block.instructions[block.instructions.length - 1];
        const b = branchInfo(last);
        if (b?.kind === 'jump') {
            if (b.target != null && b.target >= entryAddress && blockByAddr.has(b.target)) block.successors.push({ type: 'jump', address: b.target });
            else if (b.symbol) block.successors.push({ type: 'tailcall', symbol: b.symbol, address: b.target });
        } else if (b?.kind === 'cond') {
            if (b.target != null && blockByAddr.has(b.target)) block.successors.push({ type: 'true', address: b.target, condition: b.condition, source: b.source });
            if (blockByAddr.has(last.address + 4)) block.successors.push({ type: 'false', address: last.address + 4 });
        } else if (!b || !['return','terminal','ret-indirect','indirect-jump'].includes(b.kind)) {
            if (blockByAddr.has(last.address + 4)) block.successors.push({ type: 'fallthrough', address: last.address + 4 });
        }
    }
    for (const block of blocks) {
        for (const succ of block.successors) {
            const dst = blockByAddr.get(succ.address);
            if (dst) dst.predecessors.push(block.address);
        }
    }
    return { entryAddress, blocks, blockByAddr, instructions: reachable };
}

function chkIdom(entry, succOf, predOf) {
    const order = [], seen = new Set([entry]), stack = [[entry, 0, succOf(entry)]];
    while (stack.length) {
        const top = stack[stack.length - 1];
        if (top[1] < top[2].length) {
            const n = top[2][top[1]++];
            if (!seen.has(n)) { seen.add(n); stack.push([n, 0, succOf(n)]); }
        } else { order.push(top[0]); stack.pop(); }
    }
    order.reverse();
    const idx = new Map(order.map((n, i) => [n, i]));
    const idom = new Map([[entry, entry]]);
    const intersect = (x, y) => {
        while (x !== y) {
            while (idx.get(x) > idx.get(y)) x = idom.get(x);
            while (idx.get(y) > idx.get(x)) y = idom.get(y);
        }
        return x;
    };
    for (let changed = true; changed;) {
        changed = false;
        for (const n of order) {
            if (n === entry) continue;
            let nw = null;
            for (const pr of predOf(n)) {
                if (!idom.has(pr)) continue;
                nw = nw === null ? pr : intersect(pr, nw);
            }
            if (nw !== null && idom.get(n) !== nw) { idom.set(n, nw); changed = true; }
        }
    }
    return idom;
}

function computeDominators(cfg) {
    if (cfg._dom) return cfg._dom;
    const blocks = cfg.blocks, all = new Set(blocks.map(b => b.address));
    const succOf = a => (cfg.blockByAddr.get(a)?.successors || []).map(x => x.address).filter(x => cfg.blockByAddr.has(x));
    const predOf = a => (cfg.blockByAddr.get(a)?.predecessors || []).filter(x => cfg.blockByAddr.has(x));
    const idom = chkIdom(cfg.entryAddress, succOf, predOf);
    const dom = new Map();
    for (const b of blocks) {
        if (!idom.has(b.address)) { dom.set(b.address, new Set(all)); continue; }
        const set = new Set([b.address]);
        for (let x = b.address; x !== cfg.entryAddress;) { x = idom.get(x); set.add(x); }
        dom.set(b.address, set);
    }
    return cfg._dom = dom;
}

function computePostDominators(cfg) {
    if (cfg._post) return cfg._post;
    const blocks = cfg.blocks, all = new Set(blocks.map(b => b.address)), VEXIT = '__exit__';
    const exitSet = new Set(blocks.filter(b => !b.successors.some(s => cfg.blockByAddr.has(s.address)) || branchInfo(b.instructions.at(-1))?.kind === 'return').map(b => b.address));
    const csucc = a => (cfg.blockByAddr.get(a)?.successors || []).map(x => x.address).filter(x => cfg.blockByAddr.has(x));

    const succOf = a => a === VEXIT ? [...exitSet] : (cfg.blockByAddr.get(a)?.predecessors || []).filter(x => cfg.blockByAddr.has(x));
    const predOf = a => exitSet.has(a) ? [VEXIT, ...csucc(a)] : csucc(a);
    const ipdom = chkIdom(VEXIT, succOf, predOf);
    const post = new Map();
    for (const b of blocks) {
        if (!ipdom.has(b.address)) { post.set(b.address, new Set(all)); continue; }
        const set = new Set([b.address]);
        for (let x = ipdom.get(b.address); x !== VEXIT; x = ipdom.get(x)) set.add(x);
        post.set(b.address, set);
    }
    post._ipdom = new Map([...ipdom].filter(([k]) => k !== VEXIT).map(([k, v]) => [k, v === VEXIT ? null : v]));
    return cfg._post = post;
}

function computeImmediateDominators(cfg, dom = computeDominators(cfg)) {
    if (cfg._idom) return cfg._idom;
    const idom = new Map([[cfg.entryAddress, null]]);
    for (const b of cfg.blocks) {
        if (b.address === cfg.entryAddress) continue;
        const candidates = [...(dom.get(b.address) || [])].filter(x => x !== b.address);
        if (!candidates.length) { idom.set(b.address, null); continue; }
        let best = candidates[0];
        for (const c of candidates.slice(1)) {
            if ((dom.get(c)?.size ?? 0) > (dom.get(best)?.size ?? 0)) best = c;
        }
        idom.set(b.address, best);
    }
    return cfg._idom = idom;
}

function computeDominanceFrontiers(cfg, idom = computeImmediateDominators(cfg)) {
    const df = new Map(cfg.blocks.map(b => [b.address, new Set()]));
    for (const b of cfg.blocks) {
        if (b.predecessors.length < 2) continue;
        const stop = idom.get(b.address);
        for (const pred of b.predecessors) {
            let runner = pred;
            const seen = new Set();
            while (runner != null && runner !== stop && !seen.has(runner)) {
                seen.add(runner);
                df.get(runner)?.add(b.address);
                runner = idom.get(runner);
            }
        }
    }
    return df;
}

function buildSSA(cfg) {
    const regs = Array.from({length:31}, (_,i)=>`x${i}`);
    const dom = computeDominators(cfg);
    const idom = computeImmediateDominators(cfg, dom);
    const frontiers = computeDominanceFrontiers(cfg, idom);
    const defsByReg = new Map(regs.map(r=>[r,new Set()]));
    const defs = new Map(), uses = new Map();
    for (const b of cfg.blocks) {
        defs.set(b.address, []); uses.set(b.address, []);
        for (const insn of b.instructions) {
            const d = instructionRegDest(insn);
            const src = instructionSourceRegs(insn).filter(r=>regs.includes(r));
            if (d && regs.includes(d)) {
                defs.get(b.address).push({address:insn.address,reg:d,asm:insn.asm});
                defsByReg.get(d).add(b.address);
            }
            if (src.length) uses.get(b.address).push({address:insn.address,regs:src,asm:insn.asm});
        }
    }
    const phiRegs = new Map(cfg.blocks.map(b=>[b.address,new Set()]));
    for (const r of regs) {
        const work=[...defsByReg.get(r)], seen=new Set(work);
        while(work.length){
            const x=work.pop();
            for(const y of frontiers.get(x)||[]) {
                if(phiRegs.get(y).has(r)) continue;
                phiRegs.get(y).add(r);
                if(!seen.has(y)){seen.add(y);work.push(y);}
            }
        }
    }
    const phiNodes = new Map(cfg.blocks.map(b=>[b.address,{}]));
    for(const b of cfg.blocks) for(const r of phiRegs.get(b.address)||[]) phiNodes.get(b.address)[r]={version:null,incoming:{}};
    const domChildren = new Map(cfg.blocks.map(b=>[b.address,[]]));
    for(const [b,p] of idom) if(p!=null) domChildren.get(p)?.push(b);
    const stacks = new Map(regs.map(r=>[r,[0]]));
    const nextVersion = new Map(regs.map(r=>[r,1]));
    const renamedDefs = new Map(), renamedUses = new Map();
    const renameBlock = addr => {
        const b=cfg.blockByAddr.get(addr); if(!b) return;
        const pushed=[], phis=phiNodes.get(addr)||{};
        for(const r of Object.keys(phis)) {
            const n=nextVersion.get(r); nextVersion.set(r,n+1); phis[r].version=n;
            stacks.get(r).push(n); pushed.push(r);
        }
        for(const insn of b.instructions) {
            const src=instructionSourceRegs(insn).filter(r=>regs.includes(r));
            if(src.length) renamedUses.set(insn.address,src.map(r=>({reg:r,version:stacks.get(r).at(-1)})));
            const d=instructionRegDest(insn);
            if(d && regs.includes(d)) {
                const n=nextVersion.get(d); nextVersion.set(d,n+1); stacks.get(d).push(n); pushed.push(d);
                renamedDefs.set(insn.address,{reg:d,version:n});
            }
        }
        for(const succ of b.successors) {
            const ph=phiNodes.get(succ.address); if(!ph) continue;
            for(const r of Object.keys(ph)) ph[r].incoming[addr]=stacks.get(r).at(-1);
        }
        for(const child of domChildren.get(addr)||[]) renameBlock(child);
        for(let i=pushed.length-1;i>=0;i--) stacks.get(pushed[i]).pop();
    };
    renameBlock(cfg.entryAddress);
    return {dom,idom,frontiers,phiNodes,defs,uses,renamedDefs,renamedUses};
}

function immediatePostDominator(cfg, post, addr) {
    if (post._ipdom && post._ipdom.has(addr) && post.get(addr)?.size !== cfg.blocks.length) return post._ipdom.get(addr);
    const set = post.get(addr);
    if (!set) return null;
    const candidates = [...set].filter(x => x !== addr);
    let best = null;
    for (const c of candidates) {
        const cset = post.get(c);
        if (!cset) continue;
        if (best === null || cset.size > post.get(best).size) best = c;
    }
    return best;
}

function setEqual(a,b) {
    if (!a || !b || a.size !== b.size) return false;
    for (const x of a) if (!b.has(x)) return false;
    return true;
}

function hasBackEdge(cfg, from, to, dominators = null) {
    const b = cfg.blockByAddr.get(from);
    if (!b || !b.successors.some(s => s.address === to)) return false;
    if (!dominators) return from >= to;
    return dominators.get(from)?.has(to) || false;
}

let nextExprId = 1;
function node(kind, fields = {}) { return { id: nextExprId++, kind, ...fields }; }
function v(name, width = 64) { return node('var', { name, width }); }
function u32(a) { return cast('uint32_t', a, true); }
function c(value, width = 64) { return node('const', { value, width }); }
function cBig(b, width = 64) {
    b = BigInt(b);
    const n = Number(b);
    const k = c(n, width);
    if (!Number.isSafeInteger(n)) k.big = b;
    return k;
}
function constBig(e) { return e.big !== undefined ? e.big : (Number.isSafeInteger(e.value) ? BigInt(e.value) : null); }
function bitsToFloat(b, type) {
    const dv = new DataView(new ArrayBuffer(8));
    if (type === 'float') { dv.setUint32(0, Number(BigInt.asUintN(32, b))); return dv.getFloat32(0); }
    dv.setBigUint64(0, BigInt.asUintN(64, b)); return dv.getFloat64(0);
}
function floatText(x, type) {
    if (Number.isNaN(x)) return 'NAN';
    if (!Number.isFinite(x)) return x < 0 ? '-INFINITY' : 'INFINITY';
    let t = type === 'float' ? String(Math.fround(x)) : String(x);
    const r = type === 'float' ? Math.fround(x) : x;
    let best = String(r);
    if (type === 'float') { for (let p = 1; p <= 9; p++) { const q = Number(r.toPrecision(p)); if (Math.fround(q) === r) { best = String(q); break; } } }
    t = best;
    if (/^-?\d+$/.test(t)) t += '.0';
    return type === 'float' ? t + 'f' : t;
}
function unary(op, a) { return node('unary', { op, a }); }
function binary(op, a, b, meta = {}) { return node('binary', { op, a, b, ...meta }); }
function cast(type, a, implicit = false) { return node('cast', { type, a, implicit }); }
function bitcast(type, a) { return node('bitcast', { type, a }); }
function load(addr, width = 64, signed = false) { return node('load', { addr, width, signed }); }
function call(name, args, indirect = null) { return node('call', { name, args, indirect }); }
function select(cond, yes, no) { return node('select', { cond, yes, no }); }
function unknown(text) { return node('unknown', { text }); }
function phi(name, incoming = new Map(), meta = {}) { return node('phi', { name, incoming, ...meta }); }

function isFPRegisterName(name) { return /^(?:farg\d+|[dsqhbv]\d+)$/i.test(String(name||'')); }

const PREC = {
    '?:': 2, '||': 3, '&&': 4, '|': 5, '^': 6, '&': 7,
    '==': 8, '!=': 8, '<': 9, '<=': 9, '>': 9, '>=': 9, '<u': 9, '<=u': 9, '>u': 9, '>=u': 9,
    '<<': 10, '>>': 10, '>>>': 10, '+': 11, '-': 11, '*': 12, '/': 12, '%': 12,
};

function arrayAccess(e) {
    const a=e.addr;
    if(!a || a.kind!=='binary' || a.op!=='+') return null;
    const peel=x=>{ while(x && (x.kind==='cast' || x.kind==='bitcast')) x=x.a; return x; };
    for(const [b,i] of [[a.a,a.b],[a.b,a.a]]) {
        const bb=peel(b);
        if(!(bb?.kind==='var' && /^&rodata_[0-9a-f]+$/.test(bb.name||''))) continue;
        const bytes=(e.width||64)/8, ii=peel(i);
        if(ii?.kind==='binary' && ii.op==='<<' && ii.b?.kind==='const' && (1<<ii.b.value)===bytes) return {name:bb.name.slice(1),index:ii.a,bytes};
        if(bytes===1) return {name:bb.name.slice(1),index:i,bytes};
        if(ii?.kind==='binary' && ii.op==='*' && ii.b?.kind==='const' && ii.b.value===bytes) return {name:bb.name.slice(1),index:ii.a,bytes};
    }
    return null;
}

function derefText(inner) { return /^[A-Za-z_][\w$]*$/.test(inner) ? `*${inner}` : `*(${inner})`; }

function memberOffsetAccess(addr) {
    if(!addr || addr.kind!=='binary' || addr.op!=='+') return null;
    const peel=x=>{ while(x && (x.kind==='cast' || x.kind==='bitcast')) x=x.a; return x; };
    for(const [off,base] of [[addr.b,addr.a],[addr.a,addr.b]]) {
        const sym=peel(off);
        const name = sym?.kind==='var' && typeof sym.name==='string' && !sym.name.startsWith('&') ? sym.name
            : (sym?.kind==='load' && sym.addr?.kind==='var' && /^&[^.]/.test(sym.addr.name||'') ? sym.addr.name.slice(1) : null);
        if(name && /[.$]|::/.test(name)) {
            const field=name.split(/[.$]|::/).filter(Boolean).pop();
            if(field && /^[A-Za-z_][A-Za-z0-9_]*$/.test(field)) return {base,field};
        }
    }
    return null;
}

function magicDivide(e) {
    if (!e || e.kind !== 'binary' || e.op !== '>>>') return null;
    if (e._magic !== undefined) return e._magic;
    e._magic = null;
    let shn = e.b; while (shn && (shn.kind === 'cast' || shn.kind === 'bitcast')) shn = shn.a;
    if (shn?.kind !== 'const') return null;
    const sh = shn.value;
    if (!Number.isInteger(sh) || sh < 32 || sh > 48) return null;
    let m = e.a; while (m && (m.kind === 'cast' || m.kind === 'bitcast')) m = m.a;
    if (!m || m.kind !== 'binary' || m.op !== '*') return null;
    let x, k;
    const cv = n => { while (n && (n.kind === 'cast' || n.kind === 'bitcast')) n = n.a; return n?.kind === 'const' ? n.value : null; };
    if (cv(m.b) != null) { x = m.a; k = cv(m.b); } else if (cv(m.a) != null) { x = m.b; k = cv(m.a); } else return null;
    if (!Number.isFinite(k) || k <= 1) return null;
    const M = BigInt(Math.trunc(k)), S = BigInt(sh), approx = Math.round(2 ** sh / k);
    const samples = [0n, 1n, 2n, 3n, 0x7fffffffn, 0x80000000n, 0xfffffffen, 0xffffffffn];
    for (let i = 0n; i < 64n; i++) samples.push((i * 0x9e3779b1n + 12345n) & 0xffffffffn);
    for (let d = Math.max(2, approx - 1); d <= approx + 1; d++) {
        const D = BigInt(d), extra = [D - 1n, D, D + 1n, 2n * D - 1n, 2n * D, 3n * D - 1n, 3n * D, 0xffffffffn / D * D, 0xffffffffn / D * D - 1n];
        if ([...samples, ...extra].every(v => v < 0n || v > 0xffffffffn || (v * M) >> S === v / D)) return e._magic = { x, d };
    }
    return null;
}

function magicMod(e) {

    if (!e || e.kind !== 'binary' || e.op !== '-' || e.b?.kind !== 'binary' || e.b.op !== '*') return null;
    const peel = n => { while (n && (n.kind === 'cast' || n.kind === 'bitcast')) n = n.a; return n; };
    const dv = peel(e.b.b);
    if (dv?.kind !== 'const') return null;
    const md = magicDivide(peel(e.b.a));
    return md && md.d === dv.value && exprEq(md.x, e.a) ? { x: e.a, d: md.d } : null;
}

function printExpr(e, parentPrec = 0, seen = new Set()) {
    if (!e) return '/*undef*/';
    if (seen.has(e.id)) return e.kind === 'phi' ? (e.varName || e.name || `phi_${e.id}`) : `/* cycle:${e.kind}_${e.id} */`;
    seen.add(e.id);
    let s, p = 100;
    switch (e.kind) {
        case 'var': s = e.name; break;
        case 'const': s = e.big !== undefined ? '0x' + BigInt.asUintN(64, e.big).toString(16) : (e.isFloat ? floatText(e.value, e.floatType) : String(e.value)); break;
        case 'string': s = JSON.stringify(e.value); break;
        case 'selector': s = PRINT_STYLE === 'objc' ? `@selector(${e.value})` : JSON.stringify(e.value); break;
        case 'cfstring': s = PRINT_STYLE === 'objc' ? `CFSTR(${JSON.stringify(e.value)})` : JSON.stringify(e.value); break;
        case 'unknown': s = `/* ${e.text} */`; break;
        case 'raw': s = String(e.text); break;
        case 'builtin':
            p = 13; s = `${e.name}(${(e.args || []).map(a => printExpr(a, 0, seen)).join(', ')})`; break;
        case 'fpcond':
            p=13; s=`${e.name}(${printExpr(e.lhs,0,seen)}, ${printExpr(e.rhs,0,seen)})`; break;
        case 'unary':
            p = 13;
            s = e.op === '!' ? `!(${printExpr(e.a, p, seen)})` : `${e.op}(${printExpr(e.a, p, seen)})`;
            break;
        case 'bitcast':
            p = 13;
            if((e.type==='float' || e.type==='double') && e.a?.kind==='const' && constBig(e.a)!==null) s = floatText(bitsToFloat(constBig(e.a), e.type), e.type);
            else s = `((${e.type})bits(${printExpr(e.a, p, seen)}))`;
            break;
        case 'cast':
            p = 13;
            if (e.implicit) { seen.delete(e.id); const inner = printExpr(e.a, parentPrec, seen); seen.add(e.id); s = inner; p = 0; if (e.a && e.a.kind==='binary') p = 100; }
            else if ((e.type === 'uint32_t' || e.type === 'int32_t') && e.a?.kind === 'var' && !isFPRegisterName(e.a.name)) s = printExpr(e.a, p, seen);
            else s = `((${e.type})(${printExpr(e.a, p, seen)}))`;
            break;
        case 'binary':
            { const mm = magicMod(e); if (mm) { p = 12; s = `${printExpr(mm.x, 12, seen)} % ${mm.d}`; if (p < parentPrec) s = `(${s})`; break; }
              const md = magicDivide(e); if (md) { p = 12; s = `${printExpr(md.x, 12, seen)} / ${md.d}`; if (p < parentPrec) s = `(${s})`; break; } }
            p = PREC[e.op] || 10;
            if ((e.op === '/' || e.op === '%') && e.signedness) {
                const fn = e.op === '/' ? (e.signedness === 'unsigned' ? 'udiv' : 'sdiv') : (e.signedness === 'unsigned' ? 'umod' : 'smod');
                s = `${fn}(${printExpr(e.a, 0, seen)}, ${printExpr(e.b, 0, seen)})`;
                p = 13;
            } else {
                s = `${printExpr(e.a, p, seen)} ${e.op} ${printExpr(e.b, p + (['-','/','%'].includes(e.op) ? 1 : 0), seen)}`;
            }
            if (p < parentPrec) s = `(${s})`;
            break;
        case 'load':
            p = 13;
            if(e.width===128) { s=`*(uint128_t*)(${printExpr(e.addr,0,seen)})`; break; }
            const ar=arrayAccess(e);
            if(ar) { s=`${ar.name}[${printExpr(ar.index,0,seen)}]`; break; }
            const mo=memberOffsetAccess(e.addr);
            if(mo) { s=`${printExpr(mo.base,13,seen)}->${mo.field}`; break; }
            { const lb=loadBase(e); if(lb && lb.k>=0 && STRUCT_BASES.has(lb.name)) { s=`${lb.name}->f${lb.k}`; break; } }
            if(e.addr?.kind==='var' && typeof e.addr.name==='string' && /^&[^.]/.test(e.addr.name)) s=e.addr.name.slice(1);
            else if(e.addr?.kind==='binary' && e.addr.op==='+' && e.addr.a?.kind==='var' && typeof e.addr.a.name==='string' && /^&[^.]/.test(e.addr.a.name)) {
                const sym=e.addr.a.name.slice(1);
                if(e.addr.b?.kind==='const') s=`${sym}[${e.addr.b.value / Math.max(1,e.width/8)}]`;
                else s=derefText(printExpr(e.addr,0,seen));
            } else s = derefText(printExpr(e.addr, 0, seen));
            break;
        case 'call':
            p = 13;
            { let callee=demangleName(e.name);
              if(e.indirect) { const ind=printExpr(e.indirect, 0, seen); callee = /^[A-Za-z_][\w$.]*$/.test(ind) ? ind : `(${ind})`; }
              s = `${callee}(${e.args.map(a => printExpr(a, 0, seen)).join(', ')})`; }
            break;
        case 'select':
            p = PREC['?:'];
            s = `(${printExpr(e.cond, p, seen)} ? ${printExpr(e.yes, 0, seen)} : ${printExpr(e.no, 0, seen)})`;
            break;
        case 'phi': {
            const vals = [...e.incoming.values()].filter(Boolean);
            if (e.varName) s = e.varName;
            else if (!vals.length) s = e.name;
            else if (vals.every(x => x.id === vals[0].id)) s = printExpr(vals[0], parentPrec, seen);
            else if (e.condition && e.yesPred!=null && e.noPred!=null) {
                const yes=e.incoming.get(e.yesPred), no=e.incoming.get(e.noPred);
                const condText=printExpr(e.condition, PREC['?:'], seen);
                const yesText=printExpr(yes,0,seen);
                const noText=printExpr(no,0,seen);
                s=`(${condText} ? ${yesText} : ${noText})`;
            } else {
                s = `phi(${vals.map(x => printExpr(x, 0, seen)).join(', ')})`;
            }
            break;
        }
        default: s = `/* ${e.kind} */`;
    }
    seen.delete(e.id);
    return s;
}

let PRINT_STYLE = 'c';
let PRINT_TYPES = true;
let STRUCT_BASES = new Map();

function strHash(str) { let h = 5381; for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) | 0; return h; }
function exprHash(e) {
    if (!e) return 0;
    if (e._h !== undefined) return e._h;
    const m = (...xs) => { let h = 17; for (const x of xs) h = (Math.imul(h, 31) + x) | 0; return h; };
    let h;
    switch (e.kind) {
        case 'var': h = strHash(`v${e.name}/${e.width}`); break;
        case 'const': h = strHash(`c${String(e.value)}/${e.width}`); break;
        case 'unknown': case 'raw': case 'rawcond': h = strHash(`${e.kind}${e.text}`); break;
        case 'unary': h = m(strHash('u' + e.op), exprHash(e.a)); break;
        case 'cast': case 'bitcast': h = m(strHash('k' + e.type), exprHash(e.a)); break;
        case 'binary': h = m(strHash('b' + e.op), exprHash(e.a), exprHash(e.b)); break;
        case 'load': h = m(strHash(`l${e.width}${e.signed}`), exprHash(e.addr)); break;
        case 'call': h = m(strHash('f' + e.name), exprHash(e.indirect), ...(e.args || []).map(exprHash)); break;
        case 'select': h = m(7, exprHash(e.cond), exprHash(e.yes), exprHash(e.no)); break;
        case 'fpcond': h = m(strHash('p' + e.name), exprHash(e.lhs), exprHash(e.rhs)); break;
        case 'builtin': h = m(strHash('n' + e.name), ...(e.args || []).map(exprHash)); break;
        case 'phi': h = strHash('phi' + e.name); break;
        default: h = strHash(`${e.kind}#${e.id}`);
    }
    return (e._h = h);
}

function exprEq(a,b,seen=new Set()) {
    if(a===b) return true;
    if(!a || !b || a.kind!==b.kind) return false;
    if(exprHash(a)!==exprHash(b)) return false;
    const pair=`${a.id}:${b.id}`; if(seen.has(pair)) return true; seen.add(pair);
    switch(a.kind){
        case 'var': return a.name===b.name && a.width===b.width;
        case 'const': return Object.is(a.value,b.value) && a.width===b.width;
        case 'unknown': case 'raw': case 'rawcond': return a.text===b.text;
        case 'unary': return a.op===b.op && exprEq(a.a,b.a,seen);
        case 'cast': case 'bitcast': return a.type===b.type && exprEq(a.a,b.a,seen);
        case 'binary': return a.op===b.op && exprEq(a.a,b.a,seen) && exprEq(a.b,b.b,seen);
        case 'load': return a.width===b.width && a.signed===b.signed && exprEq(a.addr,b.addr,seen);
        case 'call': return a.name===b.name && exprEq(a.indirect,b.indirect,seen) && a.args.length===b.args.length && a.args.every((x,i)=>exprEq(x,b.args[i],seen));
        case 'select': return exprEq(a.cond,b.cond,seen) && exprEq(a.yes,b.yes,seen) && exprEq(a.no,b.no,seen);
        case 'fpcond': return a.name===b.name && exprEq(a.lhs,b.lhs,seen) && exprEq(a.rhs,b.rhs,seen);
        case 'builtin': return a.name===b.name && a.args.length===b.args.length && a.args.every((x,i)=>exprEq(x,b.args[i],seen));
        case 'phi': { const av=[...(a.incoming?.values?.()||[])],bv=[...(b.incoming?.values?.()||[])]; return a.name===b.name && av.length===bv.length && av.every((x,i)=>exprEq(x,bv[i],seen)); }
        default: return a.id===b.id;
    }
}

function exprContains(a, targetId, seen = new Set()) {
    if (!a || seen.has(a.id)) return false;
    if (a.id === targetId) return true;
    seen.add(a.id);
    switch (a.kind) {
        case 'unary': case 'cast': case 'bitcast': return exprContains(a.a, targetId, seen);
        case 'binary': return exprContains(a.a, targetId, seen) || exprContains(a.b, targetId, seen);
        case 'load': return exprContains(a.addr, targetId, seen);
        case 'call': return a.args.some(x => exprContains(x, targetId, seen)) || exprContains(a.indirect, targetId, seen);
        case 'select': return exprContains(a.cond,targetId,seen) || exprContains(a.yes,targetId,seen) || exprContains(a.no,targetId,seen);
        case 'phi': return [...a.incoming.values()].some(x => exprContains(x,targetId,seen));
        default: return false;
    }
}

function isBooleanExpr(e) {
    if (!e) return false;
    if (e.kind === 'const') return e.value === 0 || e.value === 1;
    if (e.kind === 'fpcond') return true;
    if (e.kind === 'rawcond') return true;
    if (e.kind === 'binary') return ['==','!=','<','<=','>','>=','<u','<=u','>u','>=u','&&','||'].includes(e.op);
    if (e.kind === 'unary' && e.op === '!') return true;
    if (e.kind === 'select') return isBooleanExpr(e.yes) && isBooleanExpr(e.no);
    return false;
}

function foldConstBig(op, a, b) {
    let r;
    switch (op) {
        case '+': r = a + b; break;
        case '-': r = a - b; break;
        case '*': r = a * b; break;
        case '&': r = a & b; break;
        case '|': r = a | b; break;
        case '^': r = a ^ b; break;
        case '<<': if (b < 0n || b > 63n) return null; r = a << b; break;
        case '>>': if (b < 0n || b > 63n) return null; r = BigInt.asIntN(64, a) >> b; break;
        case '>>>': if (b < 0n || b > 63n) return null; r = BigInt.asUintN(64, a) >> b; break;
        default: return null;
    }
    return BigInt.asIntN(64, r);
}

function foldConst(op, A, B) {
    if (!Number.isInteger(A) || !Number.isInteger(B)) {
        if (op === '+') return A + B;
        if (op === '-') return A - B;
        if (op === '*') return A * B;
        return null;
    }
    const a = BigInt(A), b = BigInt(B);
    let r;
    switch (op) {
        case '+': r = a + b; break;
        case '-': r = a - b; break;
        case '*': r = a * b; break;
        case '&': r = a & b; break;
        case '|': r = a | b; break;
        case '^': r = a ^ b; break;
        case '<<': if (b < 0n || b > 63n) return null; r = a << b; break;
        case '>>': if (b < 0n || b > 63n) return null; r = BigInt.asIntN(64, a) >> b; break;
        case '>>>': if (b < 0n || b > 63n) return null; r = BigInt.asUintN(64, a) >> b; break;
        default: return null;
    }
    const n = Number(BigInt.asIntN(64, r));
    return Number.isSafeInteger(n) ? n : null;
}

function simplifyExpr(e) {
    if (!e) return e;
    if (e.kind === 'bitcast') {
        e.a = simplifyExpr(e.a);
        if (e.a.kind === 'bitcast') return e.a.a;
        return e;
    }
    if (e.kind === 'cast') {
        e.a = simplifyExpr(e.a);
        if (e.type === 'uint32_t' && e.a.kind === 'var') return e.a;
        if (e.type === 'uint32_t' && e.a.kind === 'cast' && e.a.type === 'uint32_t') return e.a;
    }
    if (e.kind === 'binary') {
        e.a = simplifyExpr(e.a); e.b = simplifyExpr(e.b);
        if (e.a.kind === 'const' && e.b.kind === 'const' && (e.a.big !== undefined || e.b.big !== undefined) && constBig(e.a) !== null && constBig(e.b) !== null && ['+','-','*','&','|','^','<<','>>','>>>'].includes(e.op)) {
            const r = foldConstBig(e.op, constBig(e.a), constBig(e.b));
            if (r !== null) return cBig(r);
        }
        if (e.a.kind === 'const' && e.b.kind === 'const') {
            const A = e.a.value, B = e.b.value;
            switch (e.op) {
                case '/': return B === 0 ? e : c(Math.trunc(A / B));
                case '+': case '-': case '*': case '&': case '|': case '^': case '<<': case '>>': case '>>>': {
                    const r = foldConst(e.op, A, B);
                    if (r !== null) return c(r);
                    break;
                }
                case '==': return c(A === B ? 1 : 0, 32);
                case '!=': return c(A !== B ? 1 : 0, 32);
            }
        }
        if ((e.op === '<<' || e.op === '>>' || e.op === '>>>') && e.b.kind === 'const' && e.b.value === 0) return e.a;
        if (e.op === '+' && e.b.kind === 'const' && e.b.value === 0) return e.a;
        if (e.op === '-' && e.b.kind === 'const' && e.b.value === 0) return e.a;
        if (e.op === '*' && e.b.kind === 'const' && e.b.value === 1) return e.a;
        if (e.op === '|' && e.b.kind === 'const' && e.b.value === 0) return e.a;
        if (e.op === '^' && e.b.kind === 'const' && e.b.value === 0) return e.a;
    }
    if (e.kind === 'unary') {
        e.a = simplifyExpr(e.a);
        if (e.op === '-' && e.a.kind === 'unary' && e.a.op === '-') return e.a.a;
        if (e.op === '-' && e.a.kind === 'const' && Number.isFinite(e.a.value)) return e.a.value === 0 ? e.a : c(-e.a.value, e.a.width);
        if (e.op === '~' && e.a.kind === 'const' && Number.isSafeInteger(e.a.value)) return c(-e.a.value - 1, e.a.width);
    }
    if (e.kind === 'builtin') {
        e.args = (e.args || []).map(simplifyExpr);
        if (e.name === 'clz' && e.args[0]?.kind === 'builtin' && e.args[0].name === 'rbit') {
            return node('builtin', { name: 'ctz64', args: [e.args[0].args[0]] });
        }
    }
    if (e.kind === 'select') {
        e.cond = simplifyExpr(e.cond); e.yes = simplifyExpr(e.yes); e.no = simplifyExpr(e.no);
        if (exprEq(e.yes, e.no)) return e.yes;
        const one=x=>x?.kind==='const' && x.value===1;
        const zero=x=>x?.kind==='const' && x.value===0;
        if (one(e.yes) && zero(e.no)) return e.cond;
        if (zero(e.yes) && one(e.no)) return negateExpr(e.cond);
        if (zero(e.no) && isBooleanExpr(e.yes)) return binary('&&',e.cond,e.yes);
        if (one(e.no) && isBooleanExpr(e.yes)) return binary('||',negateExpr(e.cond),e.yes);
        if (one(e.yes) && isBooleanExpr(e.no)) return binary('||',e.cond,e.no);
        if (zero(e.yes) && isBooleanExpr(e.no)) return binary('&&',negateExpr(e.cond),e.no);
    }
    return e;
}

class LazyInstructionStates {
    constructor(df) { this.df = df; this.cache = new Map(); this.blockOf = null; }
    index() {
        if (this.blockOf) return;
        this.blockOf = new Map();
        for (const b of this.df.cfg.blocks) for (const i of b.instructions) this.blockOf.set(i.address, b);
    }
    get(address) {
        this.index();
        const block = this.blockOf.get(address);
        if (!block) return undefined;
        const inState = this.df.inState.get(block.address);
        if (!inState) return undefined;
        const last = block.instructions[block.instructions.length - 1];
        if (last.address === address) return this.df.outState.get(block.address) || undefined;
        const hit = this.cache.get(address);
        if (hit && hit.inState === inState) return hit.state;
        const state = inState.clone();
        for (const insn of block.instructions) {
            if (insn.address === address) break;
            const b = branchInfo(insn);
            if (b && ['jump','cond','return','terminal','ret-indirect','indirect-jump','tailcall'].includes(b.kind)) continue;
            liftInstruction(insn, state, this.df.context);
        }
        this.cache.set(address, { inState, state });
        return state;
    }
}

class State {
    constructor() {
        this.regs = new Map();
        this.fpRegs = new Map();
        this.stack = new Map();
        this.sp = v('sp');
        this.fpBase = null;
        this.spDelta = 0;
        this.flags = null;
        this.memoryVersion = 0;
        this.callVersion = 0;
        this.argWrites = new Set();
        this.fpArgWrites = new Set();
        this.savedRegs = new Map();
        this.tempCounter = 0;
    }

    clone() {
        const s = new State();
        s.regs = new Map(this.regs);
        s.fpRegs = new Map(this.fpRegs);
        s.stack = new Map(this.stack);
        s.sp = this.sp;
        s.fpBase = this.fpBase;
        s.spDelta = this.spDelta;
        s.flags = this.flags ? { ...this.flags } : null;
        s.memoryVersion = this.memoryVersion;
        s.callVersion = this.callVersion;
        s.argWrites = new Set(this.argWrites);
        s.fpArgWrites = new Set(this.fpArgWrites);
        s.savedRegs = new Map(this.savedRegs);
        s.tempCounter = this.tempCounter;
        return s;
    }
}

function flagsEqual(a,b) {
    if(a===b) return true;
    if(!a || !b || a.kind!==b.kind) return false;
    for(const k of ['lhs','rhs','value','guard']) {
        if((a[k]==null)!==(b[k]==null)) return false;
        if(a[k]!=null && !exprEq(a[k],b[k])) return false;
    }
    if((a.compare==null)!==(b.compare==null) || (a.compare && !flagsEqual(a.compare,b.compare))) return false;
    for(const k of ['op','fallback','source','thenCond','elseCond']) if(a[k]!==b[k]) return false;
    return true;
}

function abstractStateEqual(a,b) {
    if(!a || !b) return false;
    if(a.spDelta!==b.spDelta || a.fpBase!==b.fpBase) return false;
    const mapEq=(ma,mb)=>{
        if(ma.size!==mb.size) return false;
        for(const [k,vv] of ma) {
            const wv=mb.get(k);
            if(!wv && vv) return false;
            if(vv && wv && !exprEq(vv,wv)) return false;
        }
        return true;
    };
    if(!mapEq(a.regs,b.regs)||!mapEq(a.fpRegs,b.fpRegs)||!mapEq(a.stack,b.stack)) return false;
    if(!flagsEqual(a.flags,b.flags)) return false;
    return true;
}

function newEntryState() {
    const s = new State();
    for (let i = 0; i < 31; i++) s.regs.set(`x${i}`, i < 8 ? v(`arg${i}`) : v(`x${i}`));
    for (let i = 0; i < 32; i++) s.fpRegs.set(`d${i}`, i < 8 ? v(`farg${i}`) : v(`d${i}`));
    return s;
}

function readFPReg(state, reg) {
    const r = regNorm(reg);
    if (!isFPRegister(r)) return unknown(r);
    const n = Number(r.slice(1));
    let base = state.fpRegs.get(`d${n}`) || v(`d${n}`);
    if (r[0] === 's') return (base?.kind === 'cast' && base.type === 'float') || (base?.kind === 'bitcast' && base.type === 'float') ? base : cast('float', base, true);
    if (r[0] === 'd') return (base?.kind === 'cast' && base.type === 'double') || (base?.kind === 'bitcast' && base.type === 'double') ? base : cast('double', base, true);
    return base;
}

function readReg(state, reg) {
    const r = regNorm(reg);
    if (isZeroReg(r)) return c(0);
    if (isSP(r)) return state.sp;
    if (isFPRegister(r)) return readFPReg(state, r);
    const n = regIndex(r);
    if (n == null) return unknown(r);
    const x = state.regs.get(`x${n}`) || v(`x${n}`);
    if (r[0] !== 'w') return x;
    return x.kind === 'cast' && x.type === 'uint32_t' ? x.a : simplifyExpr(u32(x));
}

function writeReg(state, reg, value) {
    const r = regNorm(reg);
    if (isZeroReg(r)) return;
    if (isSP(r)) { state.sp = value; return; }
    if (isFPRegister(r)) {
        const n=Number(r.slice(1));
        const targetType=r[0]==='s'?'float':r[0]==='h'?'half':r[0]==='b'?'float':'double';
        const value2=(value?.kind==='bitcast' && value.type===targetType) ? value : ((r[0]==='s'||r[0]==='h'||r[0]==='b') ? cast(targetType,value,true) : value);
        state.fpRegs.set(`d${n}`,value2);
        if (n < 8) state.fpArgWrites.add(n);
        return;
    }
    const n = regIndex(r);
    if (n == null) return;
    state.regs.set(`x${n}`, r[0] === 'w' ? simplifyExpr(u32(value)) : value);
    if (n < 8) state.argWrites.add(n);
}

function fmtLocalOffset(offset) {
    if (offset === 0) return 'local_0';
    return offset < 0 ? `local_m${Math.abs(offset)}` : `local_p${offset}`;
}

function stackAddress(state, mem, phase = 'normal') {
    if (!mem) return null;
    let base = mem.base;
    let baseDelta = null;
    if (base === 'sp') baseDelta = state.spDelta;
    else if (base === 'x29' && state.fpBase != null) baseDelta = state.fpBase;
    else return null;
    if (phase === 'pre' && mem.writeback) baseDelta += mem.offset;
    if (phase === 'post') {

    }
    if (mem.offsetReg) return null;
    return baseDelta + mem.offset;
}

function localVar(offset) { return v(fmtLocalOffset(offset)); }

function memoryAddressExpr(state, mem) {
    if (!mem) return unknown('bad memory operand');
    const local = stackAddress(state, mem);
    if (local != null && mem.offsetReg == null) return localVar(local);
    const base = mem.base === 'sp' ? state.sp : readReg(state, mem.base);
    if (mem.offsetReg) {
        let idx = readReg(state, mem.offsetReg);
        if (mem.extend === 'uxtw') idx = cast('uint32_t', idx);
        else if (mem.extend === 'sxtw') idx = cast('int32_t', idx);
        if (mem.shift) idx = binary('<<', idx, c(mem.shift, 32));
        return binary('+', base, idx);
    }
    return mem.offset === 0 ? base : binary(mem.offset < 0 ? '-' : '+', base, c(Math.abs(mem.offset)));
}

function isLikelyFPExpr(e, seen = new Set()) {
    if (!e || seen.has(e.id)) return false;
    seen.add(e.id);
    if (e.kind === 'var') return /^farg\d+$/i.test(e.name || '') || /^(?:d|s)\d+$/i.test(e.name || '');
    if (e.kind === 'cast') return e.type === 'float' || e.type === 'double' || e.type === 'half';
    if (e.kind === 'bitcast') return e.type === 'float' || e.type === 'double';
    if (e.kind === 'call') return e.returnKind === 'fp';
    if (e.kind === 'fpcond') return true;
    if (e.fpType) return true;
    if (e.kind === 'select') return isLikelyFPExpr(e.yes, seen) || isLikelyFPExpr(e.no, seen);
    if (e.kind === 'phi') return [...(e.incoming?.values?.() || [])].some(x => isLikelyFPExpr(x, seen));
    return false;
}

function accessWidth(mnemonic, reg) {
    const m = mnemonic.toLowerCase();
    if (/^q\d+$/i.test(regNorm(reg))) return 128;
    if (m.includes('b')) return 8;
    if (m.includes('h')) return 16;
    if (m.includes('sw') || /\bw\d/.test(regNorm(reg)) || /^s\d+$/i.test(regNorm(reg))) return 32;
    if (m === 'ldrsw' || m === 'ldursw') return 32;
    return 64;
}

function signedLoadMnemonic(m) {
    return ['ldrsb','ldur sb','ldrsh','ldursh','ldrsw','ldursw'].includes(m) || m === 'ldrsb' || m === 'ldrsh' || m === 'ldrsw' || m === 'ldursb' || m === 'ldursh' || m === 'ldursw';
}

function evalNZCVCond(nzcv, code) {
    const N=(nzcv>>>3)&1, Z=(nzcv>>>2)&1, C=(nzcv>>>1)&1, V=nzcv&1;
    switch(String(code).toLowerCase()) {
        case 'eq': return Z===1;
        case 'ne': return Z===0;
        case 'cs': case 'hs': return C===1;
        case 'cc': case 'lo': return C===0;
        case 'mi': return N===1;
        case 'pl': return N===0;
        case 'vs': return V===1;
        case 'vc': return V===0;
        case 'hi': return C===1 && Z===0;
        case 'ls': return C===0 || Z===1;
        case 'ge': return N===V;
        case 'lt': return N!==V;
        case 'gt': return Z===0 && N===V;
        case 'le': return Z===1 || N!==V;
        case 'al': return true;
        case 'nv': return false;
        default: return false;
    }
}

function comparePredicate(lhs,rhs,code) {
    const cde=String(code).toLowerCase();
    if (cde==='eq') return binary('==',lhs,rhs);
    if (cde==='ne') return binary('!=',lhs,rhs);
    if (cde==='lt') return binary('<',lhs,rhs);
    if (cde==='le') return binary('<=',lhs,rhs);
    if (cde==='gt') return binary('>',lhs,rhs);
    if (cde==='ge') return binary('>=',lhs,rhs);
    if (cde==='lo' || cde==='cc') return binary('<u',lhs,rhs);
    if (cde==='hs' || cde==='cs') return binary('>=u',lhs,rhs);
    if (cde==='hi') return binary('>u',lhs,rhs);
    if (cde==='ls') return binary('<=u',lhs,rhs);
    return null;
}

function condFromFlags(cond, state) {
    const code = String(cond).toLowerCase();
    const f = state.flags;
    if (f?.kind === 'fcompare') {
        const fmap = { eq:'fp_eq', ne:'fp_ne', lt:'fp_lt', le:'fp_le', gt:'fp_gt', ge:'fp_ge', lo:'fp_lt', hs:'fp_ge', hi:'fp_gt', ls:'fp_le', cc:'fp_lt', cs:'fp_ge', mi:'fp_lt', pl:'fp_ge' };
        if (fmap[code]) return node('fpcond',{name:fmap[code],lhs:f.lhs,rhs:f.rhs});
    }
    if (f?.kind === 'compare') {
        const signed = { eq:'==', ne:'!=', lt:'<', le:'<=', gt:'>', ge:'>=' }[code];
        if (signed) return binary(signed, f.lhs, f.rhs);
        const uns = { lo:'<u', ls:'<=u', hi:'>u', hs:'>=u', cc:'<u', cs:'>=u' }[code];
        if (uns) return binary(uns, f.lhs, f.rhs);
        if (code === 'mi') return binary('<', f.value, c(0));
        if (code === 'pl') return binary('>=', f.value, c(0));
    }
    if (f?.kind === 'test') {
        if (code === 'eq') return binary('==', f.value, c(0));
        if (code === 'ne') return binary('!=', f.value, c(0));
        if (code === 'mi' || code === 'lt') return binary('<', f.value, c(0));
        if (code === 'pl' || code === 'ge') return binary('>=', f.value, c(0));
        if (code === 'gt') return binary('>', f.value, c(0));
        if (code === 'le') return binary('<=', f.value, c(0));
    }
    if (f?.kind === 'ccmp') {
        const yes = f.compare?.kind==='compare' ? comparePredicate(f.compare.lhs,f.compare.rhs,code) : null;
        const no = c(evalNZCVCond(f.fallback,code) ? 1 : 0, 32);
        if (yes) return select(f.guard, yes, no);
        return node('rawcond',{text:`ccmp_flags(${code})`});
    }
    if (f?.kind === 'conditional') {
        return node('rawcond', { text: `${printExpr(f.guard)} ? flags(${f.thenCond}) : flags(${f.elseCond})` });
    }
    return node('rawcond', { text: `FLAGS_${code}` });
}

function condFromOperand(state, operand) {
    return readReg(state, operand);
}

function negateExpr(e) {
    if (!e) return node('rawcond', { text: '!FLAGS' });
    if (e.kind === 'binary') {
        const inv = { '==':'!=','!=':'==','<':'>=','<=':'>','>': '<=','>=':'<','<u':'>=u','<=u':'>u','>u':'<=u','>=u':'<u' }[e.op];
        if (inv) return binary(inv, e.a, e.b);
        if (e.op === '&&') return binary('||', negateExpr(e.a), negateExpr(e.b));
        if (e.op === '||') return binary('&&', negateExpr(e.a), negateExpr(e.b));
    }
    if (e.kind === 'unary' && e.op === '!') return e.a;
    return unary('!', e);
}

function branchCondition(insn, state) {
    const m = insn.mnemonic, o = insn.operands;
    if (isCondBranch(m)) return condFromFlags(m.slice(2), state);
    if (m === 'cbz' || m === 'cbnz') {
        const x = readReg(state, o[0]);
        return binary(m === 'cbnz' ? '!=' : '==', x, c(0));
    }
    if (m === 'tbz' || m === 'tbnz') {
        const x = readReg(state, o[0]);
        const bit = parseAsmImm(o[1]) ?? 0;
        const t = binary('&', x, binary('<<', c(1, bit >= 31 ? 64 : 32), c(bit,32)));
        return binary(m === 'tbnz' ? '!=' : '==', t, c(0));
    }
    return null;
}

function indirectFunctionName(expr) {
    if(expr?.kind==='var' && typeof expr.name==='string' && expr.name.startsWith('&')) return expr.name.slice(1);
    return null;
}

function relocCallName(insn, targetNameFn) {
    if (insn.relocation?.symbol) return insn.relocation.symbol;
    const target = directTarget(insn);
    if (target != null) return targetNameFn?.(target) || `sub_${target.toString(16)}`;
    return 'sub_unknown';
}

function stackPointerOffset(state, expr, seen=new Set()) {
    if(!expr || seen.has(expr.id)) return null;
    seen.add(expr.id);
    if(expr.kind==='var') {
        if(expr.name==='sp') return 0;
        if(typeof expr.name==='string' && /^&local_(?:m\d+|p\d+|0)$/.test(expr.name)) {
            const m=/^&local_(m\d+|p\d+|0)$/.exec(expr.name);
            if(m) { if(m[1]==='0') return 0; return m[1][0]==='m' ? -Number(m[1].slice(1)) : Number(m[1].slice(1)); }
        }
        return null;
    }
    if(expr.kind==='binary' && (expr.op==='+' || expr.op==='-')) {
        const base=stackPointerOffset(state,expr.a,seen);
        if(base!=null && expr.b?.kind==='const') return base + (expr.op==='+' ? expr.b.value : -expr.b.value);
    }
    return null;
}

function inferCallArgCountFromState(state, fallback=8) {
    if (!(state?.argWrites instanceof Set) || state.argWrites.size === 0) return Math.min(fallback, 0);
    return Math.max(...state.argWrites) + 1;
}

function collectCallArgs(state, argc=8) {
    const args=[];
    for(let i=0;i<argc;i++) {
        const e=readReg(state,`x${i}`);
        if(e?.kind==='unknown' && i>0) break;
        args.push(e);
        if(e?.kind==='unknown') break;
    }
    return args;
}

function inferFPCallArgCountFromState(state, fallback=8) {
    if (!(state?.fpArgWrites instanceof Set) || state.fpArgWrites.size === 0) return 0;
    return Math.max(...state.fpArgWrites) + 1;
}

function collectFPCallArgs(state, argc=8) {
    const args=[];
    for(let i=0;i<argc;i++) {
        const e=readFPReg(state,`d${i}`);
        args.push(e);
    }
    return args;
}

function absoluteAddressOfExpr(expr, seen=new Set()) {
    if(!expr || seen.has(expr.id)) return null;
    seen.add(expr.id);
    if(expr.kind==='const' && Number.isFinite(expr.value)) return Number(expr.value);
    if(expr.kind==='binary' && (expr.op==='+' || expr.op==='-') && expr.b?.kind==='const') {
        const base=absoluteAddressOfExpr(expr.a,seen);
        return base==null ? null : base + (expr.op==='+' ? expr.b.value : -expr.b.value);
    }
    return null;
}

function liftInstruction(insn, state, ctx) {
    const out = liftInstructionCore(insn, state, ctx);
    const m = insn.mnemonic, o = insn.operands || [];
    if (/^(?:ldr|ldur|str|stur|ldp|stp|ldpsw|ldnp|stnp)/.test(m)) {
        const mi = o.findIndex(x => String(x).trim().startsWith('['));
        const mem = mi >= 0 ? parseMem(o[mi]) : null;

        const post = mem && mem.postIndex == null && !mem.writeback && o[mi + 1] != null && parseAsmImm(o[mi + 1]) != null ? parseAsmImm(o[mi + 1]) : (mem ? mem.postIndex : null);
        if (mem && !mem.offsetReg && !isSP(mem.base) && (mem.writeback || post != null)) {
            const delta = mem.writeback ? mem.offset : post;
            if (delta) {
                const base = readReg(state, mem.base);
                writeReg(state, mem.base, simplifyExpr(binary(delta < 0 ? '-' : '+', base, c(Math.abs(delta)))));
            }
        }
    }
    return out;
}

function liftInstructionCore(insn, state, ctx) {
    const m = insn.mnemonic, o = insn.operands;
    const statements = [];
    const emit = (kind, data) => statements.push({ kind, ...data, address: insn.address, asm: insn.asm });

    const addressExpr = (address) => {
        const target=ctx?.image?.addressTarget ? ctx.image.addressTarget(address) : null;
        if(target?.kind==='symbol') return v(`&${target.name}`,64);
        if(target?.kind==='global') return v(`&${target.name}`,64);
        if(target?.kind==='function') return v(target.name,64);
        if(target?.kind==='rodata') return v(`&${target.name}`,64);
        if(target?.kind==='string') return node('string',{value:target.value,address});
        if(target?.kind==='selector') return node('selector',{value:target.value,address});
        if(target?.kind==='cfstring') return node('cfstring',{value:target.value,address});
        return c(address,64);
    };

    const resolvedMemoryAddress = (mem) => {
        if(!mem || mem.offsetReg || mem.base==='sp' || mem.base==='x29') return null;
        const base=readReg(state,mem.base);
        const baseAddr=absoluteAddressOfExpr(base);
        if(baseAddr==null) return null;
        const address=baseAddr+mem.offset;
        const target=ctx?.image?.addressTarget ? ctx.image.addressTarget(address) : null;
        if(target?.kind==='symbol') return v(`&${target.name}`,64);
        if(target?.kind==='string') return node('string',{value:target.value,address});
        if(target?.kind==='selector') return node('selector',{value:target.value,address});
        if(target?.kind==='cfstring') return node('cfstring',{value:target.value,address});
        const globalName=ctx?.image?.globalAddressName ? ctx.image.globalAddressName(address) : null;
        if(globalName) return v(`&${globalName}`,64);
        return c(address,64);
    };

    const fpConstExpr = (address, reg) => {
        const r=regNorm(reg)[0];
        if(r!=='d' && r!=='s') return null;
        const width=r==='d' ? 64 : 32;
        const bits=ctx?.image?.readonlyBitsAt ? ctx.image.readonlyBitsAt(address,width) : null;
        if(bits==null) return null;
        const type=r==='d' ? 'double' : 'float';
        const k=c(bitsToFloat(bits,type),64);
        k.isFloat=true; k.floatType=type;
        return k;
    };

    const literalLoadExpr = (address) => {
        const target=ctx?.image?.addressTarget ? ctx.image.addressTarget(address) : null;
        if(target?.kind==='symbol') {
            const sec=ctx.image.meta.sections?.find(sec=>address>=sec.addr && address<sec.addr+sec.size);
            if(sec && [0x6,0x7,0x10].includes(sec.flags & 0xff)) return v(`&${target.name}`,64);
            return v(target.name,64);
        }
        if(target?.kind==='global') return load(v(`&${target.name}`,64),64,false);
        if(target?.kind==='selector') return node('selector',{value:target.value,address});
        if(target?.kind==='string') return node('string',{value:target.value,address});
        return c(address,64);
    };

    const fpOpExpr = (index) => {
        const text=String(o[index] ?? '').trim();
        if(isFPRegister(text)) return readReg(state,text);
        const imm=parseFloatImm(text);
        if(imm!=null) return c(imm,64);
        return node('raw',{text});
    };

    const opExpr = (index) => {
        const p = parseShiftOperand(o, index);
        if (!p) return unknown(`operand ${index}`);
        let e = isRegister(p.operand) ? readReg(state, p.operand) : (parseAsmImm(p.operand) != null ? c(parseAsmImm(p.operand)) : node('raw', { text: p.operand }));
        if (p.shift) {
            if (p.shift === 'lsl') e = binary('<<', e, c(p.amount, 32));
            else if (p.shift === 'lsr') e = binary('>>>', e, c(p.amount, 32));
            else if (p.shift === 'asr') e = binary('>>', e, c(p.amount, 32));
        }
        return simplifyExpr(e);
    };

    if (m === 'nop' || m === 'hint' || m === 'yield' || m === 'wfe' || m === 'wfi' || m === 'sev' || m === 'sevl') return statements;

    if (m === 'fmov' && o.length >= 2) {
        const dst=o[0], srcOp=o[1];
        let src, dstIsFP=isFPRegister(dst), srcIsFP=isFPRegister(srcOp);
        if (dstIsFP && srcIsFP) src=readFPReg(state,srcOp);
        else if (dstIsFP && !srcIsFP) {
            const fimm=parseAsmImm(srcOp)==null ? parseFloatImm(srcOp) : null;
            if (fimm!=null) { src=c(fimm,64); src.isFloat=true; }
            else {
                src=parseAsmImm(srcOp)!=null ? c(parseAsmImm(srcOp),32) : readReg(state,srcOp);
                src=bitcast(/^s\d+$/i.test(dst)?'float':'double',src);
            }
        } else if (!dstIsFP && srcIsFP) {
            src=bitcast(/^w\d+$/i.test(dst)?'uint32_t':'uint64_t',readFPReg(state,srcOp));
        } else {
            src=parseAsmImm(srcOp)!=null ? c(parseAsmImm(srcOp)) : readReg(state,srcOp);
        }
        src=simplifyExpr(src);
        writeReg(state,dst,src); emit('assign',{dst:canonicalReg(dst),expr:src,hideTemp:true}); return statements;
    }
    if (['fadd','fsub','fmul','fdiv'].includes(m) && o.length>=3) {
        const a=readFPReg(state,o[1]), b=readFPReg(state,o[2]);
        const op={fadd:'+',fsub:'-',fmul:'*',fdiv:'/'}[m];
        const expr=binary(op,a,b); expr.fpType=/^s\d+$/i.test(o[0])?'float':'double'; writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (m==='fneg' && o.length>=2) {
        const expr=unary('-',readFPReg(state,o[1])); expr.fpType=/^s\d+$/i.test(o[0])?'float':'double'; writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (['fmadd','fmsub','fnmadd','fnmsub'].includes(m) && o.length>=4) {
        const x=readFPReg(state,o[1]), y=readFPReg(state,o[2]), z=readFPReg(state,o[3]);
        const t=/^s\d+$/i.test(o[0])?'float':'double';
        const mul=binary('*',x,y); mul.fpType=t;
        let expr;
        if (m==='fmadd') expr=binary('+',z,mul);
        else if (m==='fmsub') expr=binary('-',z,mul);
        else if (m==='fnmadd') { const sum=binary('+',z,mul); sum.fpType=t; expr=unary('-',sum); }
        else { const d=binary('-',mul,z); expr=d; }
        expr.fpType=t; writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (['fabs','fsqrt','frintm','frintp','frintz','frinta','frintx','frinti','frintn','fmax','fmin','fmaxnm','fminnm'].includes(m) && o.length>=2) {
        const t=/^s\d+$/i.test(o[0])?'float':'double';
        const f=t==='float'?'f':'';
        const name={fabs:'fabs',fsqrt:'sqrt',frintm:'floor',frintp:'ceil',frintz:'trunc',frinta:'round',frintx:'rint',frinti:'nearbyint',frintn:'roundeven',fmax:'fmax',fmin:'fmin',fmaxnm:'fmax',fminnm:'fmin'}[m]+f;
        const args=[readFPReg(state,o[1])]; if(o.length>=3) args.push(readFPReg(state,o[2]));
        const expr=node('builtin',{name,args}); expr.fpType=t; writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (m==='fcvt' && o.length>=2) {
        const t=/^s\d+$/i.test(o[0])?'float':/^h\d+$/i.test(o[0])?'_Float16':'double';
        const expr=cast(t,readFPReg(state,o[1]),false); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if ((m==='movi' || m==='mvni') && o.length>=2 && /^v\d+\.(?:8b|16b|4h|8h|2s|4s|1d|2d)$/i.test(String(o[0]).trim())) {
        const arr=/\.(\w+)$/.exec(String(o[0]).trim())[1].toLowerCase();
        const imm=parseAsmImmBig(o[1]);
        if (imm!=null) {
            const lsl=/(lsl|msl)\s*#?(\d+)/i.exec(o[2]||'');
            let lane=BigInt.asUintN(64,imm);
            if (lsl) lane=lsl[1].toLowerCase()==='lsl' ? (lane<<BigInt(lsl[2])) : (((lane+1n)<<BigInt(lsl[2]))-1n);
            const esz={b:8,h:16,s:32,d:64}[arr.slice(-1)];
            const emask=(1n<<BigInt(esz))-1n;
            lane&=emask;
            if (m==='mvni') lane=~lane&emask;
            const count=esz===64 ? (arr[0]==='1'?1:2) : (arr.length===2?Number(arr[0]):Number(arr.slice(0,-1)));
            let wide=0n; for(let i=0;i<count;i++) wide|=lane<<BigInt(i*esz);
            const expr=cBig(wide,128);
            const n=Number(String(o[0]).trim().slice(1).split('.')[0]);
            state.fpRegs.set(`d${n}`,expr);
            emit('assign',{dst:`v${n}`,expr,hideTemp:true}); return statements;
        }
    }
    if (m==='fcmp' && o.length>=2) {
        const a=fpOpExpr(0), b=fpOpExpr(1);
        state.flags={kind:'fcompare',lhs:a,rhs:b}; return statements;
    }
    if (m==='fcsel' && o.length>=4) {
        const cond=condFromFlags(o[3].toLowerCase(),state);
        const expr=select(cond,readFPReg(state,o[1]),readFPReg(state,o[2]));
        writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (m==='scvtf' || m==='ucvtf') {
        const src=readReg(state,o[1]); const type=m==='scvtf'?'double':'double';
        const expr=cast(type,src,false); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (m==='fcvtzs' || m==='fcvtzu') {
        const src=readReg(state,o[1]); const type=m==='fcvtzs'?'int32_t':'uint32_t';
        const expr=cast(type,src,false); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }

    if ((m === 'movz' || m === 'movn' || m === 'movk') && o.length >= 2) {
        const imm = parseAsmImm(o[1]);
        const sh = /lsl\s*#?(\d+)/i.exec(o[2] || '');
        const shift = sh ? Number(sh[1]) : 0;
        const wide = !/^w/i.test(String(o[0]).trim());
        const bits = wide ? 64 : 32;
        const mask = (1n << BigInt(bits)) - 1n;
        const fit = v => { const sv = wide ? BigInt.asIntN(64, v) : BigInt.asUintN(32, v); return cBig(sv, bits); };
        let expr = null;
        if (imm != null) {
            const chunk = (BigInt(imm) & 0xffffn) << BigInt(shift);
            if (m === 'movz') expr = fit(chunk);
            else if (m === 'movn') expr = fit(~chunk & mask);
            else {
                const old = readReg(state, o[0]);
                const hole = ~(0xffffn << BigInt(shift)) & mask;
                if (old?.kind === 'const' && constBig(old) !== null) expr = fit((BigInt.asUintN(bits, constBig(old)) & hole) | chunk);
                else expr = simplifyExpr(binary('|', binary('&', old, c(Number(hole & 0xffffffffn), 32)), c(Number(chunk), bits)));
            }
        }
        if (!expr) expr = node('raw', { text: `${m}(${o.join(', ')})` });
        writeReg(state, o[0], expr);
        emit('assign', { dst: canonicalReg(o[0]), expr, hideTemp: true });
        return statements;
    }

    if (m === 'mov' && o.length >= 2) {
        const dst = o[0]; let src = isRegister(o[1]) ? readReg(state,o[1]) : (parseAsmImmBig(o[1]) != null ? cBig(parseAsmImmBig(o[1])) : node('raw',{text:o[1]}));
        if(canonicalReg(dst)==='x29' && isSP(o[1])) { state.fpBase=state.spDelta; writeReg(state,dst,src); emit('frame',{op:'fp-mov'}); return statements; }
        if(isSP(o[1])) src=v(`&${fmtLocalOffset(state.spDelta)}`,64);
        const dreg=canonicalReg(dst);

        if(/^x(?:19|20)$/.test(dreg) && src?.kind==='call') {
            state.tempCounter=(state.tempCounter||0)+1;
            const tmp=v(`tmp_obj${state.tempCounter}`,64);
            writeReg(state,dst,tmp);

            writeReg(state,'x0',tmp);
            emit('assign',{dst:tmp,expr:src,hideTemp:false});
            return statements;
        }
        writeReg(state, dst, src);
        emit('assign', { dst: canonicalReg(dst), expr: src, hideTemp: true });
        return statements;
    }

    if ((m === 'add' || m === 'sub') && o.length >= 3) {
        const dst = o[0];
        const a = opExpr(1), b = opExpr(2);
        if (isSP(dst) && isSP(o[1]) && parseAsmImm(o[2]) != null) {
            state.spDelta += m === 'sub' ? -parseAsmImm(o[2]) : parseAsmImm(o[2]);
            state.sp = binary(m === 'sub' ? '-' : '+', state.sp, c(Math.abs(parseAsmImm(o[2]))));
            emit('frame', { op: m, amount: parseAsmImm(o[2]) });
            return statements;
        }
        if (canonicalReg(dst) === 'x29' && isSP(o[1]) && parseAsmImm(o[2]) != null) {
            state.fpBase = state.spDelta + (m === 'add' ? parseAsmImm(o[2]) : -parseAsmImm(o[2]));
            const expr = simplifyExpr(binary(m === 'sub' ? '-' : '+', a,b));
            writeReg(state,dst,expr);
            emit('frame',{op:'fp',amount:parseAsmImm(o[2])});
            return statements;
        }
        let expr;
        const imm=parseAsmImm(o[2]);
        const baseOffset=isSP(o[1]) ? state.spDelta : stackPointerOffset(state,a);
        if(m==='add' && a?.kind==='const' && a.isPage && imm!=null && !insn.relocation) {

            expr=addressExpr(a.value+imm);
        } else if(baseOffset!=null && imm!=null) {
            const targetOffset=baseOffset + (m==='sub' ? -imm : imm);
            expr=v(`&${fmtLocalOffset(targetOffset)}`,64);
        } else {
            expr = simplifyExpr(binary(m === 'sub' ? '-' : '+', a,b));
        }
        writeReg(state,dst,expr);
        emit('assign',{dst:canonicalReg(dst),expr,hideTemp:true});
        return statements;
    }

    if ((m === 'adds' || m === 'subs') && o.length >= 3) {
        const dst=o[0], a=opExpr(1), b=opExpr(2);
        const expr=simplifyExpr(binary(m === 'subs' ? '-' : '+',a,b));
        state.flags={kind:'compare',lhs:a,rhs:m === 'subs' ? b : simplifyExpr(unary('-',b)),value:expr,op:m === 'subs' ? '-' : '+'};
        if (!isZeroReg(dst)) {
            writeReg(state,dst,expr);
            emit('assign',{dst:canonicalReg(dst),expr,hideTemp:true,flags:true});
        }
        return statements;
    }

    if (m === 'cmp' && o.length >= 2) {
        const a=opExpr(0), b=opExpr(1);
        state.flags={kind:'compare',lhs:a,rhs:b,value:binary('-',a,b),op:'-'};
        return statements;
    }
    if (m === 'cmn' && o.length >= 2) {
        const a=opExpr(0), b=opExpr(1), expr=binary('+',a,b);
        state.flags={kind:'compare',lhs:a,rhs:unary('-',b),value:expr,op:'+'};
        return statements;
    }
    if (m === 'tst' && o.length >= 2) {
        const a=opExpr(0), b=opExpr(1), expr=binary('&',a,b);
        state.flags={kind:'test',value:expr};
        return statements;
    }
    if (m === 'ccmp' || m === 'ccmn') {
        const guard=condFromFlags(o[3],state);
        const lhs=opExpr(0), rhs=opExpr(1);
        const compareKind=m==='ccmp'?'compare':'compare';
        const compare={kind:compareKind,lhs,rhs:m==='ccmp'?rhs:simplifyExpr(unary('-',rhs)),op:m==='ccmp'?'-':'+'};
        const fallback=parseAsmImm(o[2]) ?? 0;
        state.flags={kind:'ccmp',guard,compare,fallback,source:m};
        return statements;
    }

    const arithmetic = {
        and:'&', ands:'&', bics:'&', orr:'|', eor:'^', bic:'&', orn:'|', eon:'^', mul:'*', sdiv:'/', udiv:'/',
        madd:'madd', msub:'msub', adc:'adc', adcs:'adc', sbc:'sbc', sbcs:'sbc', umull:'*', smull:'*', umulh:'umulh', smulh:'smulh'
    };
    if (Object.prototype.hasOwnProperty.call(arithmetic,m) && o.length >= 3) {
        let expr;
        if (m === 'umull') expr=binary('*',cast('uint32_t',opExpr(1)),cast('uint32_t',opExpr(2)));
        else if (m === 'smull') expr=binary('*',cast('int32_t',opExpr(1)),cast('int32_t',opExpr(2)));
        else if (m === 'umulh') expr=node('builtin',{name:'umulh64',args:[opExpr(1),opExpr(2)]});
        else if (m === 'smulh') expr=node('builtin',{name:'smulh64',args:[opExpr(1),opExpr(2)]});
        else if (m === 'madd') expr=binary('+',binary('*',opExpr(1),opExpr(2)),opExpr(3));
        else if (m === 'msub') {
            const q=opExpr(1), divisor=opExpr(2), dividend=opExpr(3);
            if (q?.kind === 'binary' && q.op === '/' && q.signedness && exprEq(q.b, divisor) && exprEq(q.a, dividend)) expr=binary('%',dividend,divisor,{signedness:q.signedness});
            else expr=binary('-',dividend,binary('*',q,divisor));
        }
        else if (m === 'adc' || m === 'adcs') expr=binary('+',binary('+',opExpr(1),opExpr(2)),node('rawcond',{text:'carry'}));
        else if (m === 'sbc' || m === 'sbcs') expr=binary('-',binary('-',opExpr(1),opExpr(2)),node('rawcond',{text:'1 - carry'}));
        else if (m === 'sdiv' || m === 'udiv') expr=binary('/',opExpr(1),opExpr(2),{signedness:m === 'sdiv' ? 'signed' : 'unsigned'});
        else if (m === 'bic' || m === 'bics') expr=binary('&',opExpr(1),unary('~',opExpr(2)));
        else if (m === 'orn') expr=binary('|',opExpr(1),unary('~',opExpr(2)));
        else if (m === 'eon') expr=binary('^',opExpr(1),unary('~',opExpr(2)));
        else expr=binary(arithmetic[m],opExpr(1),opExpr(2));
        expr=simplifyExpr(expr);
        if (m === 'ands' || m === 'bics') state.flags={kind:'test',value:expr};
        else if (m === 'adcs' || m === 'sbcs') state.flags=null;
        writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }

    if ((m === 'neg' || m === 'negs') && o.length >= 2) {
        const src=opExpr(1), expr=unary('-',src);
        if (m === 'negs') state.flags={kind:'compare',lhs:c(0),rhs:src,value:expr,op:'-'};
        writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (m === 'mvn' && o.length >= 2) {
        const expr=unary('~',opExpr(1)); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if ((m === 'lsl' || m === 'lsr' || m === 'asr') && o.length >= 3) {
        const expr=binary(m === 'lsl' ? '<<' : m === 'lsr' ? '>>>' : '>>',opExpr(1),opExpr(2)); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (m === 'ror' && o.length >= 3) {
        const expr=node('builtin',{name:'rotr64',args:[opExpr(1),opExpr(2)]}); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (m === 'extr' && o.length >= 4) {
        const l=opExpr(1), r=opExpr(2), sh=parseAsmImm(o[3]);
        const bits=/^x/i.test(o[0])?64:32;
        const expr=sh===0 ? l : binary('|',binary('>>>',l,c(sh,32)),binary('<<',r,c(bits-sh,32)));
        writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (['uxtb','uxth','uxtw','sxtb','sxth','sxtw'].includes(m) && o.length >= 2) {
        const types={uxtb:'uint8_t',uxth:'uint16_t',uxtw:'uint32_t',sxtb:'int8_t',sxth:'int16_t',sxtw:'int32_t'};
        const expr=cast(types[m],opExpr(1)); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (['rev','rev16','rev32','rev64','rbit','clz','cls'].includes(m) && o.length >= 2) {
        const expr=node('builtin',{name:m,args:[opExpr(1)]}); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }

    if (m === 'csel' && o.length >= 4) {
        const cond=condFromFlags(o[3],state); const expr=select(cond,opExpr(1),opExpr(2)); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (m === 'csinc' && o.length >= 4) {
        const cond=condFromFlags(o[3],state); const expr=select(cond,opExpr(1),binary('+',opExpr(2),c(1))); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (m === 'csinv' && o.length >= 4) {
        const cond=condFromFlags(o[3],state); const expr=select(cond,opExpr(1),unary('~',opExpr(2))); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (m === 'csneg' && o.length >= 4) {
        const cond=condFromFlags(o[3],state); const expr=select(cond,opExpr(1),unary('-',opExpr(2))); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if (['cinc','cinv','cneg'].includes(m) && o.length >= 3) {
        const cond=condFromFlags(o[2],state); const base=opExpr(1);
        const other=m==='cinc'?binary('+',base,c(1)):m==='cinv'?unary('~',base):unary('-',base);
        const expr=select(cond,other,base); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }
    if ((m === 'cset' || m === 'csetm') && o.length >= 2) {
        const cond=condFromFlags(o[1],state); const expr=select(cond,c(m==='csetm'?-1:1,32),c(0,32)); writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }

    if (['ubfx','sbfx','ubfiz','sbfiz','bfi','bfxil'].includes(m) && o.length >= 4) {
        const src=opExpr(1), lsb=parseAsmImm(o[2]) ?? 0, width=parseAsmImm(o[3]) ?? 0, mask=width >= 63 ? -1 : (2 ** width - 1);
        let expr;
        if (m === 'ubfx') expr=binary('&',binary('>>>',src,c(lsb,32)),c(mask));
        else if (m === 'sbfx') expr=cast(`int${width}`,binary('&',binary('>>>',src,c(lsb,32)),c(mask)));
        else if (m === 'ubfiz') expr=binary('<<',binary('&',src,c(mask)),c(lsb,32));
        else if (m === 'sbfiz') expr=binary('<<',cast(`int${width}`,binary('&',src,c(mask))),c(lsb,32));
        else {
            const old=readReg(state,o[0]);
            if (width <= 0 || lsb + width > 52) expr=node('builtin',{name:m,args:[old,opExpr(1),c(lsb,32),c(width,32)]});
            else if (m === 'bfi') {
                const field=2 ** width - 1;
                expr=binary('|',binary('&',old,unary('~',c(field * 2 ** lsb))),binary('<<',binary('&',opExpr(1),c(field)),c(lsb,32)));
            } else {
                const field=2 ** width - 1;
                expr=binary('|',binary('&',old,unary('~',c(field))),binary('&',binary('>>>',opExpr(1),c(lsb,32)),c(field)));
            }
        }
        writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }

    if (m === 'stp' || m === 'ldp' || m === 'stnp' || m === 'ldnp') {
        const mem=parseMem(o[2]);
        if (!mem) return [{kind:'raw',text:`/* ${insn.asm} */`,address:insn.address,asm:insn.asm}];
        const off1=stackAddress(state,mem);
        if (off1==null) {

            const w=accessWidth(m,o[0]), bytes=w/8, a1=memoryAddressExpr(state,mem), a2=simplifyExpr(binary('+',a1,c(bytes)));
            if (m==='stp' || m==='stnp') {
                emit('store',{dst:load(a1,w,false),expr:readReg(state,o[0])});
                emit('store',{dst:load(a2,w,false),expr:readReg(state,o[1])});
            } else {
                const la=simplifyExpr(load(a1,w,false)), lb=simplifyExpr(load(a2,w,false));
                writeReg(state,o[0],la); writeReg(state,o[1],lb);
                emit('load',{dst:canonicalReg(o[0]),expr:la,hidden:true});
                emit('load',{dst:canonicalReg(o[1]),expr:lb,hidden:true});
            }
            return statements;
        }
        if (mem.writeback && mem.offset !== 0 && mem.base === 'sp' && mem.postIndex == null) state.spDelta += mem.offset;
        const off2=off1==null?null:off1 + accessWidth(m,o[0]) / 8;
        const dstA=localVar(off1 ?? 0), dstB=localVar(off2 ?? 0);
        const spillPair=(isCalleeSavedReg(o[0]) || canonicalReg(o[0])==='x29') && (canonicalReg(o[1])==='x30' || isCalleeSavedReg(o[1]));
        if(m==='stp') {
            if(!spillPair) {
                const a=readReg(state,o[0]), b=readReg(state,o[1]);
                if(off1!=null){
                    state.stack.set(String(off1),a);
                    if(isCalleeSavedReg(o[0])) state.savedRegs.set(canonicalReg(o[0]),off1);
                    emit('store',{dst:dstA,expr:a,hidden:isCalleeSavedReg(o[0])});
                }
                if(off2!=null){
                    state.stack.set(String(off2),b);
                    if(isCalleeSavedReg(o[1])) state.savedRegs.set(canonicalReg(o[1]),off2);
                    emit('store',{dst:dstB,expr:b,hidden:isCalleeSavedReg(o[1])});
                }
            }
        } else {
            if(!spillPair) {
                if(off1!=null){
                    const r=canonicalReg(o[0]);
                    const va=state.stack.get(String(off1))||load(memoryAddressExpr(state,mem),accessWidth(m,o[0]));
                    writeReg(state,o[0],va);
                    if(isCalleeSavedReg(r) && state.savedRegs.get(r)===off1) emit('restore',{reg:r,hidden:true});
                }
                if(off2!=null){
                    const r=canonicalReg(o[1]);
                    const va=state.stack.get(String(off2))||unknown(`stack_${off2}`);
                    writeReg(state,o[1],va);
                    if(isCalleeSavedReg(r) && state.savedRegs.get(r)===off2) emit('restore',{reg:r,hidden:true});
                }
            }
        }
        if(mem.postIndex!=null && mem.base==='sp') state.spDelta += mem.postIndex;
        return statements;
    }

    if (m === 'ldr' && o.length >= 2 && parseAsmImm(o[1]) != null && /^#/.test(String(o[1]).trim())) {
        const target=insn.address + parseAsmImm(o[1]);
        const expr=fpConstExpr(target,o[0]) || literalLoadExpr(target);
        writeReg(state,o[0],expr);
        emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true});
        return statements;
    }

    const loadM = /^(ldrb|ldrh|ldrsb|ldrsh|ldrsw|ldr|ldur|ldurb|ldurh|ldursb|ldursh|ldursw)$/.test(m);
    if (loadM && o.length >= 2) {
        const mem=parseMem(o[1]);
        const off=stackAddress(state,mem);
        let expr;
        if (off != null && !mem.offsetReg) {
            const saved=state.stack.get(String(off));

            if (saved?.kind==='var' && typeof saved.name==='string' && saved.name.startsWith('&')) expr=saved;
            else if (saved && isFPRegister(o[0])) {
                if (isLikelyFPExpr(saved)) expr=saved;
                else expr=bitcast(/^s\d+$/i.test(o[0])?'float':'double', saved);
            } else expr=localVar(off);
        } else if (isFPRegister(o[0]) && !mem.offsetReg && (m==='ldr'||m==='ldur') && absoluteAddressOfExpr(readReg(state,mem.base))!=null && fpConstExpr(absoluteAddressOfExpr(readReg(state,mem.base))+mem.offset,o[0])) {
            expr=fpConstExpr(absoluteAddressOfExpr(readReg(state,mem.base))+mem.offset,o[0]);
        } else {
            const width=accessWidth(m,o[0]);
            if (insn.relocation?.type === R_AARCH64_LD64_GOT_LO12_NC && insn.relocation.symbol) {

                expr=v(`&${insn.relocation.symbol}`,64);
            } else {
                const resolved=resolvedMemoryAddress(mem);
                expr=resolved?.kind==='var' && typeof resolved.name==='string' && resolved.name.startsWith('&')
                    ? load(resolved,width,/^ldr(sb|sh|sw|u?sb|u?sh)/.test(m) || ['ldrsb','ldrsh','ldrsw','ldursb','ldursh','ldursw'].includes(m))
                    : (resolved ? resolved : load(memoryAddressExpr(state,mem),width,/^ldr(sb|sh|sw|u?sb|u?sh)/.test(m) || ['ldrsb','ldrsh','ldrsw','ldursb','ldursh','ldursw'].includes(m)));
            }
            if (['ldrsb','ldrsh','ldrsw','ldursb','ldursh','ldursw'].includes(m)) {
                const castType={ldrsb:'int8_t',ldrsh:'int16_t',ldrsw:'int32_t',ldursb:'int8_t',ldursh:'int16_t',ldursw:'int32_t'}[m];
                expr=cast(castType,expr);
            }
        }
        if (isFPRegister(o[0]) && off == null && expr?.kind !== 'bitcast' && expr?.kind !== 'load' && !(expr?.kind==='const' && expr.isFloat) && !/^q\d+$/i.test(regNorm(o[0]))) expr=bitcast(/^s\d+$/i.test(o[0])?'float':'double',expr);
        writeReg(state,o[0],simplifyExpr(expr));
        expr=simplifyExpr(expr);
        const restored=isCalleeSavedReg(o[0]) && off!=null && state.savedRegs.get(canonicalReg(o[0]))===off;
        emit('load',{dst:canonicalReg(o[0]),expr,hidden:true,restored});
        if (mem?.writeback && mem.base === 'sp') state.spDelta += mem.offset;
        if (mem?.postIndex != null && mem.base === 'sp') state.spDelta += mem.postIndex;
        return statements;
    }

    const storeM = /^(str|strb|strh|stur|sturb|sturh)$/.test(m);
    if (storeM && o.length >= 2) {
        const mem=parseMem(o[1]);
        const expr=readReg(state,o[0]);
        const off=stackAddress(state,mem);
        if (off != null && !mem.offsetReg) {
            state.stack.set(String(off),expr);
            const saved=isCalleeSavedReg(o[0]);
            if(saved) state.savedRegs.set(canonicalReg(o[0]),off);
            const tempAddress=(expr?.kind==='var' && typeof expr.name==='string' && expr.name.startsWith('&'));
            emit('store',{dst:localVar(off),expr,hidden:saved||tempAddress,hideTemp:saved||tempAddress});
        } else {
            { const w=accessWidth(m,o[0]);
              const target=resolvedMemoryAddress(mem);
              const dstExpr=(target && target.kind==='var' && typeof target.name==='string' && target.name.startsWith('&'))
                  ? target
                  : load(target || memoryAddressExpr(state,mem),w,false);
              emit('store',{dst:dstExpr,expr}); }
        }
        if (mem?.writeback && mem.base === 'sp') state.spDelta += mem.offset;
        if (mem?.postIndex != null && mem.base === 'sp') state.spDelta += mem.postIndex;
        return statements;
    }

    if (m === 'adr' || m === 'adrp') {
        const value=o[1] || '#0';
        const sym=insn.relocation?.symbol;
        let expr;
        if(sym) expr=v(`&${sym}`);
        else if(m==='adr' && parseAsmImm(value)!=null) expr=addressExpr(insn.address + parseAsmImm(value));
        else if(m==='adrp' && parseAsmImm(value)!=null) { expr=c(Math.floor(insn.address / 4096) * 4096 + parseAsmImm(value),64); expr.isPage=true; }
        else expr=node('raw',{text:`&${String(value).replace(/^#/,'')}`});
        writeReg(state,o[0],expr); emit('assign',{dst:canonicalReg(o[0]),expr,hideTemp:true}); return statements;
    }

    if (m === 'bl') {
        const name=relocCallName(insn,ctx?.codeSymbolAt || ctx?.functionNameAt);
        const target=directTarget(insn);
        const knownArgc=ctx?.functionArgCountFor ? ctx.functionArgCountFor(name,target) : null;
        const knownFPArgc=ctx?.functionFPArgCountFor ? ctx.functionFPArgCountFor(name,target) : null;
        const stateArgc=inferCallArgCountFromState(state,8);
        let argc=knownArgc != null ? knownArgc : (stateArgc || ctx?.currentFunctionArgCount || 0);
        const fpStateArgc=inferFPCallArgCountFromState(state,8);
        const fpArgc=knownFPArgc != null ? knownFPArgc : (fpStateArgc || ctx?.currentFunctionFPArgCount || 0);
        const args=collectCallArgs(state,argc);
        const fpArgs=collectFPCallArgs(state,fpArgc);
        const returnReg=ctx?.functionReturnRegFor ? ctx.functionReturnRegFor(name,target) : null;
        const effectiveReturnReg=returnReg || ((/^d?0$/i.test(ctx?.returnReg||'') || /^(?:d|s)0$/i.test(ctx?.returnReg||'')) ? ctx.returnReg : null);
        const returnFP=/^(?:d|s)0$/i.test(effectiveReturnReg||'');
        const callExpr=call(name,[...args,...fpArgs]); callExpr.argClasses={int:argc,fp:fpArgc}; callExpr.returnKind=returnFP?'fp':'int';

        for (let i=0;i<=18;i++) if(i!==0) state.regs.set(`x${i}`, unknown(`x${i} after call`));
        state.regs.set('x30', unknown('x30 after call'));
        for (let i=0;i<32;i++) if(i<8 || i>=16) state.fpRegs.set(`d${i}`, unknown(`d${i} after call`));
        state.flags=null; state.callVersion++; state.argWrites.clear(); state.fpArgWrites.clear();
        if(returnFP) writeReg(state,effectiveReturnReg||'d0',callExpr); else writeReg(state,'x0',callExpr);
        state.argWrites.clear(); state.fpArgWrites.clear();
        emit('call',{expr:callExpr,result:returnFP?returnReg:'x0'});
        return statements;
    }
    if (m === 'blr') {
        const fn=readReg(state,o[0]);
        { const ti=regIndex(o[0]); if(ti!=null && ti>0 && state.argWrites instanceof Set) state.argWrites.delete(ti); }
        let argc=inferCallArgCountFromState(state,8) || ctx?.currentFunctionArgCount || 0;

        for(let i=argc, lim=Math.min(8,argc+1); i<lim && ctx?.touchedArgRegs?.has(i); i++) {
            const e=state.regs.get(`x${i}`);
            if(e===undefined || (e.kind==='var' && e.name===`arg${i}`)) argc=i+1; else break;
        }
        const fpArgc=inferFPCallArgCountFromState(state,8) || ctx?.currentFunctionFPArgCount || 0;
        const args=[...collectCallArgs(state,argc),...collectFPCallArgs(state,fpArgc)];
        const directName=indirectFunctionName(fn);
        const expr=call(directName,args,directName?null:fn); expr.argClasses={int:argc,fp:fpArgc}; expr.returnKind=/^(?:d|s)0$/i.test(ctx?.returnReg||'')?'fp':'int';
        for(let i=0;i<=18;i++) if(i!==0) state.regs.set(`x${i}`,unknown(`x${i} after indirect call`));
        state.regs.set('x30',unknown('x30 after indirect call'));
        for(let i=0;i<32;i++) if(i<8 || i>=16) state.fpRegs.set(`d${i}`,unknown(`d${i} after indirect call`));
        state.flags=null; state.callVersion++; state.argWrites.clear(); state.fpArgWrites.clear();
        if(expr.returnKind==='fp') writeReg(state,'d0',expr); else writeReg(state,'x0',expr);
        state.argWrites.clear(); state.fpArgWrites.clear();
        emit('call',{expr,result:expr.returnKind==='fp'?'d0':'x0'});
        return statements;
    }

    return [{kind:'raw',text:`/* ${insn.asm} */`,address:insn.address,asm:insn.asm}];
}

function isTempReg(reg) {
    const n=regIndex(reg);
    return n != null && n >= 8 && n <= 17;
}

class Dataflow {
    constructor(cfg, context) {
        this.cfg=cfg;
        this.context=context;
        this.inState=new Map();
        this.outState=new Map();
        this.blockStatements=new Map();
        this.instructionStates=new LazyInstructionStates(this);
        this.phis=new Map();
        this.iterations=0;
    }

    phiFor(block, key, incoming) {
        const k=`${block.address}:${key}`;
        let p=this.phis.get(k);
        if(!p) { p=phi(key,new Map()); this.phis.set(k,p); }
        p.blockAddr=block.address;
        p.incoming=new Map(incoming);
        return p;
    }

    findMergeCondition(block) {
        if (block.predecessors.length !== 2) return null;
        const resolveArm=(start)=>{
            let cur=start;
            const seen=new Set();
            for(let depth=0; depth<16 && !seen.has(cur); depth++) {
                seen.add(cur);
                const b=this.cfg.blockByAddr.get(cur);
                if(!b) return null;
                const term=blockTerminal(b);
                if(term?.kind==='cond') return {branch:b,first:cur};
                if(b.predecessors.length!==1) return null;
                const prev=b.predecessors[0];
                const pb=this.cfg.blockByAddr.get(prev);
                if(!pb) return null;
                const pe=pb.successors.find(x=>x.address===b.address);
                if(pe?.type!=='jump' && pe?.type!=='fallthrough' && pe?.type!=='true' && pe?.type!=='false') return null;
                cur=prev;
            }
            return null;
        };
        const arms=block.predecessors.map(pred=>({pred,arm:resolveArm(pred)}));
        if(arms.some(x=>!x.arm)) return null;
        const branches=arms.map(x=>x.arm.branch.address);
        if(branches[0]!==branches[1]) return null;
        const branch=arms[0].arm.branch;
        const edges=branch.successors.filter(x=>x.type==='true'||x.type==='false');
        if(edges.length!==2) return null;
        const reaches=(start,target)=>{
            const q=[start], seen=new Set([start]);
            while(q.length){
                const a=q.shift(); if(a===target) return true;
                const b=this.cfg.blockByAddr.get(a); if(!b) continue;
                for(const e of b.successors){
                    if(e.address===block.address) continue;
                    if(!seen.has(e.address) && e.address!==block.address){seen.add(e.address);q.push(e.address);}
                }
            }
            return false;
        };
        const trueArm=arms.find(x=>reaches(edges.find(e=>e.type==='true').address,x.pred));
        const falseArm=arms.find(x=>reaches(edges.find(e=>e.type==='false').address,x.pred));
        if(!trueArm || !falseArm) return null;
        const st=this.instructionStates.get(branch.instructions.at(-1).address)||this.inState.get(branch.address)||newEntryState();
        return {condition:branchCondition(branch.instructions.at(-1),st),yesPred:trueArm.pred,noPred:falseArm.pred};
    }

    phiForWithEdgeCondition(block, key, incoming) {
        const k=`${block.address}:${key}`;
        let p=this.phis.get(k);
        if(!p) { p=phi(key,new Map()); this.phis.set(k,p); }
        p.blockAddr=block.address;
        p.incoming=new Map(incoming);
        if(block.predecessors.length===2) {
            let cache=this._mcCache;
            if(!cache || cache.iter!==this.iterations || cache.addr!==block.address) {
                let info=null;
                const edges=block.predecessors.map(pred=>{
                    const pb=this.cfg.blockByAddr.get(pred);
                    const edge=pb?.successors.find(x=>x.address===block.address);
                    return {pred,edge};
                });
                const te=edges.find(x=>x.edge?.type==='true');
                const fe=edges.find(x=>x.edge?.type==='false');
                if(te && fe) {
                    const pb=this.cfg.blockByAddr.get(te.pred);
                    const ins=pb?.instructions.at(-1);
                    const st=this.outState.get(te.pred)||this.inState.get(te.pred)||newEntryState();
                    info={condition:branchCondition(ins,st),yesPred:te.pred,noPred:fe.pred};
                } else {
                    const mc=this.findMergeCondition(block);
                    if(mc) info={condition:mc.condition,yesPred:mc.yesPred,noPred:mc.noPred};
                }
                cache=this._mcCache={iter:this.iterations,addr:block.address,info};
            }
            if(cache.info) { p.condition=cache.info.condition; p.yesPred=cache.info.yesPred; p.noPred=cache.info.noPred; }
        }
        return p;
    }

    mergeStates(block) {
        if (block.address===this.cfg.entryAddress) return newEntryState();
        const preds=block.predecessors.filter(p=>this.outState.has(p));
        if (!preds.length) return newEntryState();
        if (preds.length===1) return this.outState.get(preds[0]).clone();
        const out=new State();
        for(let i=0;i<31;i++) {
            const vals=preds.map(p=>this.outState.get(p).regs.get(`x${i}`) || v(`x${i}`));
            const first=vals[0];
            if(vals.every(x=>exprEq(x,first))) out.regs.set(`x${i}`,first);
            else {
                const incoming=new Map(preds.map((p,j)=>[p,vals[j]]));
                out.regs.set(`x${i}`,this.phiForWithEdgeCondition(block,`x${i}`,incoming));
            }
        }
        for(let i=0;i<32;i++) {
            const vals=preds.map(p=>this.outState.get(p).fpRegs.get(`d${i}`) || v(`d${i}`));
            const first=vals[0];
            if(vals.every(x=>exprEq(x,first))) out.fpRegs.set(`d${i}`,first);
            else out.fpRegs.set(`d${i}`,this.phiForWithEdgeCondition(block,`d${i}`,new Map(preds.map((p,j)=>[p,vals[j]]))));
        }
        const spVals=preds.map(p=>this.outState.get(p).sp);
        out.sp=spVals.every(x=>exprEq(x,spVals[0]))?spVals[0]:this.phiFor(block,'sp',new Map(preds.map((p,j)=>[p,spVals[j]])));
        const stackKeys=new Set(); for(const p of preds) for(const k of this.outState.get(p).stack.keys()) stackKeys.add(k);
        for(const k of stackKeys) {
            const vals=preds.map(p=>this.outState.get(p).stack.get(k)||localVar(Number(k)));
            const first=vals[0];
            if(vals.every(x=>exprEq(x,first))) out.stack.set(k,first);
            else out.stack.set(k,this.phiForWithEdgeCondition(block,`stack_${k}`,new Map(preds.map((p,j)=>[p,vals[j]]))));
        }
        out.spDelta=preds.every(p=>this.outState.get(p).spDelta===this.outState.get(preds[0]).spDelta)?this.outState.get(preds[0]).spDelta:0;
        out.fpBase=preds.every(p=>this.outState.get(p).fpBase===this.outState.get(preds[0]).fpBase)?this.outState.get(preds[0]).fpBase:null;
        const flags=preds.map(p=>this.outState.get(p).flags);
        out.flags=flags.every(x=>flagsEqual(x,flags[0]))?flags[0]:null;
        for(const p of preds) {
            const ps=this.outState.get(p);
            for(const n of ps.argWrites) out.argWrites.add(n);
            for(const n of ps.fpArgWrites) out.fpArgWrites.add(n);
        }
        out.tempCounter=Math.max(...preds.map(p=>this.outState.get(p).tempCounter));
        for(const [k,val] of this.outState.get(preds[0]).savedRegs) {
            if(preds.every(p=>this.outState.get(p).savedRegs.get(k)===val)) out.savedRegs.set(k,val);
        }
        out.memoryVersion=Math.max(...preds.map(p=>this.outState.get(p).memoryVersion));
        out.callVersion=Math.max(...preds.map(p=>this.outState.get(p).callVersion));
        return out;
    }

    run() {
        const q=[this.cfg.entryAddress]; const queued=new Set(q);
        const rpo=new Map(); { const order=[], seen=new Set([this.cfg.entryAddress]), st=[[this.cfg.entryAddress,0]];
            while(st.length) { const t=st[st.length-1], b=this.cfg.blockByAddr.get(t[0]); const succ=(b?.successors||[]).map(x=>x.address).filter(x=>this.cfg.blockByAddr.has(x));
                if(t[1]<succ.length) { const n=succ[t[1]++]; if(!seen.has(n)) { seen.add(n); st.push([n,0]); } } else { order.push(t[0]); st.pop(); } }
            order.reverse().forEach((a,i)=>rpo.set(a,i)); }
        while(q.length && this.iterations++ < 100000) {
            let bi=0; for(let i=1;i<q.length;i++) if((rpo.get(q[i])??1e9)<(rpo.get(q[bi])??1e9)) bi=i;
            const addr=q.splice(bi,1)[0]; queued.delete(addr);
            const block=this.cfg.blockByAddr.get(addr); if(!block) continue;
            const incoming=this.mergeStates(block);

            const previous=this.inState.get(addr);
            if(previous && abstractStateEqual(previous,incoming)) continue;
            this.inState.set(addr,incoming);
            const state=incoming.clone();
            const statements=[];
            for(const insn of block.instructions) {
                const b=branchInfo(insn);
                if(b && ['jump','cond','return','terminal','ret-indirect','indirect-jump','tailcall'].includes(b.kind)) continue;
                statements.push(...liftInstruction(insn,state,this.context));
            }
            this.outState.set(addr,state);
            this.blockStatements.set(addr,statements);
            for(const s of block.successors) {
                if(!this.cfg.blockByAddr.has(s.address)) continue;
                if(!queued.has(s.address)) { q.push(s.address); queued.add(s.address); }
            }
        }
        return this;
    }

    getState(addr) { return this.outState.get(addr) || this.inState.get(addr) || null; }
}

function stmt(kind, fields={}) { return { kind, ...fields }; }

function statementsFromIR(ir, stateAtBlock, keepTempRegs = new Set()) {
    const out=[];
    for(const s of ir || []) {
        if(s.hidden || s.restored) continue;
        switch(s.kind) {
            case 'assign': {
                const dstName=typeof s.dst==='string' ? s.dst : s.dst?.name;
                const keep=keepTempRegs.has(dstName);
                const abiCarrier=/^(?:x|w|d|s)0$/i.test(String(dstName||''));
                const hideTemp=keep ? false : (abiCarrier ? true : !!s.hideTemp);
                const dst=(s.dst && typeof s.dst==='object') ? s.dst : v(s.dst);
                out.push(stmt('assign',{dst,expr:s.expr,hideTemp}));
                break;
            }
            case 'store': out.push(stmt('assign',{dst:s.dst,expr:s.expr,hideTemp:s.hideTemp||false})); break;
            case 'call': out.push(stmt('expr',{expr:s.expr})); break;
            case 'frame': break;
            case 'load': break;
            case 'raw': out.push(stmt('raw',{text:s.text})); break;
            default: if(s.text) out.push(stmt('raw',{text:s.text}));
        }
    }
    return out;
}

function blockTerminal(block) { return branchInfo(block.instructions.at(-1)); }
function blockIsReturn(block) { const b=blockTerminal(block); return b?.kind==='return'; }

function invertBranchCondition(code) {
    const map={eq:'ne',ne:'eq',cs:'cc',hs:'lo',cc:'cs',lo:'hs',mi:'pl',pl:'mi',vs:'vc',vc:'vs',hi:'ls',ls:'hi',ge:'lt',lt:'ge',gt:'le',le:'gt',al:'nv',nv:'al'};
    return map[code] || null;
}

class Structurer {
    constructor(cfg, df, context) {
        this.cfg=cfg; this.df=df; this.context=context;
        this.dom=computeDominators(cfg); this.post=computePostDominators(cfg);
        this.emitted=new Set();
        this.structuringKeys=new Set();
        this.visited=new Set();
        this.labelTargets=null;
    }

    tailCallTarget(term) {
        if(!term || term.kind!=='jump') return false;
        if(term.symbol) return true;
        return term.target!=null && !this.cfg.blockByAddr.has(term.target);
    }

    tailCall(block, addr) {
        const last=block.instructions.at(-1), term=blockTerminal(block);
        const st=(this.df.outState.get(addr)||newEntryState()).clone();
        const fake={...last,mnemonic:'bl',asm:String(last.asm||'b').replace(/^b\b/,'bl')};
        let ir=null;
        try { ir=liftInstruction(fake,st,this.context); } catch(e) { ir=null; }
        const callStmt=(ir||[]).find(x=>x.kind==='call');
        if(callStmt) return [stmt('return',{expr:callStmt.expr})];
        const target=term.target;
        const name=term.symbol || this.context.functionNameAt?.(target) || this.context.codeSymbolAt?.(target) || `sub_${Number(target).toString(16)}`;
        const known=this.context.functionArgCountFor?.(name,target) ?? null;
        const argc=known!=null ? known : (inferCallArgCountFromState(st,8) || this.context.currentFunctionArgCount || 0);
        return [stmt('return',{expr:call(name,collectCallArgs(st,argc))})];
    }

    edgeStmts(from,to) {
        const l=this.df.phiCopies?.get(`${from}>${to}`);
        return l ? l.map(x=>({...x})) : [];
    }

    pathStmts(from,start,limit=32) {
        const out=[...this.edgeStmts(from,start)];
        let addr=start; const seen=new Set();
        for(let i=0;i<limit && !seen.has(addr);i++) {
            seen.add(addr);
            const b=this.cfg.blockByAddr.get(addr);
            if(!b || b.instructions.length!==1) break;
            const term=blockTerminal(b);
            if(term?.kind==='jump' && term.target!=null && this.cfg.blockByAddr.has(term.target)) {
                out.push(...this.edgeStmts(addr,term.target)); addr=term.target;
            } else break;
        }
        return out;
    }

    cachedBody(addr) {
        const cache=this.df._bodyCache || (this.df._bodyCache=new Map());
        let b=cache.get(addr);
        if(!b) { b=statementsFromIR(this.df.blockStatements.get(addr),this.df.outState.get(addr)); cache.set(addr,b); }
        return b.map(x=>({...x}));
    }

    noReturnArm(addr) {
        const b=this.cfg.blockByAddr.get(addr);
        if(!b) return false;
        if(b.successors.some(x=>this.cfg.blockByAddr.has(x.address))) return false;
        return blockTerminal(b)?.kind==='call';
    }

    stackFailTarget(addr) {
        const first=this.cfg.blockByAddr.get(addr)?.instructions?.[0];
        if(first?.mnemonic!=='bl') return false;
        const target=directTarget(first);
        const name=first.relocation?.symbol || (target!=null ? (this.context.image?.codeSymbolAt?.(target) || this.context.codeSymbolAt?.(target)) : null);
        return !!name && /stack_chk_fail/.test(name);
    }

    edgeCondition(block, succType) {
        const term=blockTerminal(block);
        const state=this.df.outState.get(block.address) || this.df.inState.get(block.address) || newEntryState();
        return branchCondition(term,state);
    }

    immediateJoin(block) { return immediatePostDominator(this.cfg,this.post,block.address); }

    isLoopHeader(block) {
        return block.predecessors.some(p => hasBackEdge(this.cfg,p,block.address,this.dom));
    }

    backPreds(block) {
        return block.predecessors.filter(p => hasBackEdge(this.cfg,p,block.address,this.dom));
    }

    reaches(start,target,stop=null) {
        if(start===target) return true;
        const q=[start], seen=new Set([start]);
        while(q.length) {
            const a=q.shift(); if(a===stop) continue;
            const b=this.cfg.blockByAddr.get(a); if(!b) continue;
            for(const s of b.successors) {
                if(s.address===target) return true;
                if(!seen.has(s.address) && s.address!==stop) { seen.add(s.address); q.push(s.address); }
            }
        }
        return false;
    }

    reachesBackedge(start, header) {
        const cache=this.cfg._rb || (this.cfg._rb=new Map()), ck=`${start}|${header}`;
        if(cache.has(ck)) return cache.get(ck);
        const r=this.reachesBackedgeUncached(start,header);
        cache.set(ck,r); return r;
    }

    reachesBackedgeUncached(start, header) {
        const q=[start], seen=new Set([start]);
        while(q.length) {
            const a=q.shift();
            if(a===header) continue;
            const b=this.cfg.blockByAddr.get(a); if(!b) continue;
            for(const s of b.successors) {
                if(s.address===header && this.dom.get(a)?.has(header)) return true;
                if(!seen.has(s.address) && s.address!==header) { seen.add(s.address); q.push(s.address); }
            }
        }
        return false;
    }

    followTrivialJumps(start, limit=32) {
        let addr=start; const seen=new Set();
        for(let i=0;i<limit;i++) {
            if(seen.has(addr)) return addr; seen.add(addr);
            const b=this.cfg.blockByAddr.get(addr); if(!b) return addr;
            if(b.instructions.length!==1) return addr;
            const term=blockTerminal(b);
            if(term?.kind==='jump' && term.target!=null && this.cfg.blockByAddr.has(term.target)) { addr=term.target; continue; }
            return addr;
        }
        return addr;
    }

    collectLoop(header, backPreds) {
        const headerAddr = typeof header === 'number' ? header : header.address;
        const body=new Set([headerAddr]);
        const work=[...backPreds];
        while(work.length) {
            const a=work.pop();
            if(body.has(a)) continue;
            if(!this.dom.get(a)?.has(headerAddr)) continue;
            body.add(a);
            const b=this.cfg.blockByAddr.get(a);
            if(!b) continue;
            for(const p of b.predecessors) if(!body.has(p)) work.push(p);
        }
        return body;
    }

    detectDoWhile(start, region=null) {
        let addr=start;
        const seen=new Set();
        for(let depth=0; depth<256 && !seen.has(addr); depth++) {
            seen.add(addr);
            if(region && !region.has(addr)) return null;
            const b=this.cfg.blockByAddr.get(addr);
            if(!b) return null;
            const term=blockTerminal(b);
            if(term?.kind==='cond') {
                const back=b.successors.find(e=>e.address===start);
                if(back) {
                    const exit=b.successors.find(e=>e.address!==start);
                    if(!exit) return null;
                    const st=this.df.instructionStates.get(b.instructions.at(-1).address)||this.df.outState.get(addr)||this.df.inState.get(addr)||newEntryState();
                    let cond=branchCondition(b.instructions.at(-1),st);
                    if(back.type==='false') cond=negateExpr(cond);
                    return {condAddress:addr,exitAddress:exit.address,condition:cond,selfBlock:addr===start};
                }
                return null;
            }
            if(b.successors.length!==1) return null;
            addr=b.successors[0].address;
        }
        return null;
    }

    blockBody(addr) {
        const ir=this.df.blockStatements.get(addr)||[];
        const st=this.df.outState.get(addr)||this.df.inState.get(addr)||newEntryState();
        return statementsFromIR(ir,st).filter(x=>!(x.kind==='assign'&&x.hideTemp));
    }

    stateBeforeInstruction(address) {
        return this.df.instructionStates.get(address) || this.df.inState.get(address) || newEntryState();
    }

    findIndirectDispatch(start) {
        const q=[start], seen=new Set();
        while(q.length) {
            const addr=q.shift();
            if(seen.has(addr)) continue; seen.add(addr);
            const b=this.cfg.blockByAddr.get(addr); if(!b) continue;
            const term=blockTerminal(b);
            if(term?.kind==='indirect-jump') return b;
            if(b.instructions.length===1 && term?.kind==='jump') {
                if(term.target!=null && this.cfg.blockByAddr.has(term.target)) q.push(term.target);
                continue;
            }
            return null;
        }
        return null;
    }

    exprMatchAddScaledLoad(e) {
        if(!e || e.kind!=='binary' || e.op!=='+') return null;
        const trySide=(base,other)=>{
            if(other?.kind!=='binary' || other.op!=='<<' || other.b?.kind!=='const' || other.b.value!==2) return null;
            const l=other.a;
            const loadNode=(l?.kind==='load') ? l : (l?.kind==='cast' && l.implicit && l.a?.kind==='load' ? l.a : null);
            if(!loadNode) return null;
            return {base, load:loadNode};
        };
        return trySide(e.a,e.b) || trySide(e.b,e.a);
    }

    constExprValue(e) {
        if(!e) return null;
        if(e.kind==='const') return e.value;
        if(e.kind==='raw' && /^&(?:0x[0-9a-f]+|\d+)$/i.test(e.text)) return parseNum(e.text.slice(1));
        return null;
    }

    simulateUnreachedBlock(block, seed) {
        const state=(seed || newEntryState()).clone();
        const statements=[];
        for(const insn of block.instructions) {
            const b=branchInfo(insn);
            if(b && ['jump','cond','return','terminal','ret-indirect','indirect-jump','tailcall'].includes(b.kind)) continue;
            statements.push(...liftInstruction(insn,state,this.context));
        }
        return {state,statements};
    }

    switchCaseTail(target) {
        const b=this.cfg.blockByAddr.get(target);
        if(!b) return [stmt('raw',{text:`/* invalid switch target ${hex64(target)} */`})];
        const hasDfState=this.df.outState.has(target);
        const sim=hasDfState ? null : this.simulateUnreachedBlock(b,this.switchSeedState);
        const st=hasDfState ? this.df.outState.get(target) : sim.state;
        const ir=hasDfState ? this.df.blockStatements.get(target) : sim.statements;
        const body=statementsFromIR(ir,st).filter(x=>{
            if(x.kind==='assign' && x.hideTemp) return false;
            return true;
        });
        const term=blockTerminal(b);
        if(term?.kind==='jump' && term.symbol) {
            const known=this.context.functionArgCountFor?.(term.symbol,term.target) ?? null;
            const argc=known!=null ? known : (inferCallArgCountFromState(st,8) || this.context.currentFunctionArgCount || 0);
            return [...body,stmt('return',{expr:call(term.symbol,collectCallArgs(st,argc))})];
        }
        if(term?.kind==='return') {
            return [...body,stmt('return',{expr:readReg(st,'x0')})];
        }
        return this.buildStatements(target,null,null,0,null);
    }

    detectSwitch(block) {
        const term=blockTerminal(block);
        if(term?.kind!=='cond' || !['b.hi','b.hs'].includes(term.source)) return null;
        const state=this.stateBeforeInstruction(block.instructions.at(-1).address);
        const cond=branchCondition(block.instructions.at(-1),state);
        if(cond?.kind!=='binary' || !['>u','>=u'].includes(cond.op) || cond.b?.kind!=='const') return null;
        const maxOrCount=cond.b.value;
        const maxCase=cond.op==='>u' ? maxOrCount : maxOrCount-1;
        if(maxCase<0 || maxCase>4095) return null;
        const inRangeSucc=block.successors.find(x=>x.type==='false');
        const defaultSucc=block.successors.find(x=>x.type==='true');
        if(!inRangeSucc || !defaultSucc) return null;
        const dispatch=this.findIndirectDispatch(inRangeSucc.address);
        if(!dispatch) return null;
        const brTerm=blockTerminal(dispatch);
        const brState=this.stateBeforeInstruction(dispatch.instructions.at(-1).address);
        this.switchSeedState=brState.clone();
        const targetExpr=readReg(brState,brTerm.reg||'x0');
        const m=this.exprMatchAddScaledLoad(targetExpr);
        if(!m) return null;
        const tableLoad=m.load;
        if(!tableLoad.addr) return null;

        let sectionName=null, tableBaseOffset=0;
        const findSym=e=>{
            if(!e) return;
            if(e.kind==='var' && typeof e.name==='string' && e.name.startsWith('&.')) sectionName=e.name.slice(1);
            if(e.kind==='binary' && e.op==='+') { findSym(e.a); if(e.b?.kind==='const') tableBaseOffset+=e.b.value; findSym(e.b); }
        };
        findSym(tableLoad.addr);
        if(!sectionName) return null;
        const sec=this.context.image?.sectionByName(sectionName);
        if(!sec) return null;

        let branchBase=null;
        for(const insn of dispatch.instructions) {
            if(insn.mnemonic==='adr') {
                const d=parseAsmImm(insn.operands[1]);
                if(d!=null) branchBase=insn.address+d;
            }
        }
        if(branchBase==null) return null;

        const loadBaseOff=this.extractSectionOffset(tableLoad.addr,sectionName);
        const tableOff=loadBaseOff + tableBaseOffset;
        if(loadBaseOff==null) return null;
        const entryWidth=tableLoad.width;
        const stride=entryWidth/8;
        if(![8,16,32].includes(entryWidth)) return null;
        const cases=[];
        for(let i=0;i<=maxCase;i++) {
            const off=tableOff + i*stride;
            const value=this.context.image.readSectionValue(sectionName,off,entryWidth,!!tableLoad.signed);
            if(value==null) return null;
            const target=branchBase + value*4;
            if(!this.cfg.blockByAddr.has(target)) return null;
            cases.push({value:i,target,body:this.switchCaseTail(target)});
        }
        const defaultBody=this.switchCaseTail(defaultSucc.address);
        return {expr: cond.a || unknown('switch index'), cases, defaultBody};
    }

    extractSectionOffset(e,sectionName) {
        if(!e) return null;
        if(e.kind==='var' && e.name===`&${sectionName}`) return 0;
        if(e.kind==='binary' && e.op==='+') {
            const a=this.extractSectionOffset(e.a,sectionName);
            if(a!=null) return a + (e.b?.kind==='const' ? e.b.value : 0);
            const b=this.extractSectionOffset(e.b,sectionName);
            if(b!=null) return b + (e.a?.kind==='const' ? e.a.value : 0);
        }
        if(e.kind==='binary' && e.op==='-') {
            const a=this.extractSectionOffset(e.a,sectionName);
            if(a!=null && e.b?.kind==='const') return a-e.b.value;
        }
        return null;
    }

    buildStatements(entry=this.cfg.entryAddress, stop=null, region=null, depth=0, control=null) {
        if(entry===stop) return [];
        if(depth>64) return [stmt('raw',{text:'/* structuring depth limit */'})];
        const key=`${entry}|${stop??'end'}|${control?.header??''}|${control?.exit??''}`;

        if(this.structuringKeys.has(key)) return [stmt('goto',{target:entry})];
        this.structuringKeys.add(key);
        const out=[];
        let addr=entry;
        const localSeen=new Set();
        while(addr!=null && addr!==stop && !localSeen.has(addr)) {
            if(region && !region.has(addr)) {
                if(control?.exit===addr) out.push(stmt('break'));
                else if(this.cfg.blockByAddr.has(addr)) out.push(stmt('goto',{target:addr}));
                break;
            }
            localSeen.add(addr);
            this.visited.add(addr);
            if(this.labelTargets?.has(addr)) out.push(stmt('label',{target:addr}));
            if(!control?.suppressDoWhile) {
                const dw=this.detectDoWhile(addr,region);
                if(dw && dw.condAddress!==stop) {
                    const eBack=this.edgeStmts(dw.condAddress,addr), eExit=this.edgeStmts(dw.condAddress,dw.exitAddress);
                    let body;
                    if(dw.selfBlock) body=this.blockBody(addr);
                    else {
                        body=this.buildStatements(addr,dw.condAddress,region,depth+1,{...(control||{}),header:eBack.length?null:dw.condAddress,exit:dw.exitAddress,suppressDoWhile:true});
                        body.push(...this.blockBody(dw.condAddress));
                    }
                    if(!eBack.length) out.push(stmt('doWhile',{cond:dw.condition,body}),...eExit);
                    else out.push(stmt('while',{cond:c(1),body:[...body,stmt('if',{cond:negateExpr(dw.condition),then:[...eExit,stmt('break')],else:[]}),...eBack]}));
                    addr=dw.exitAddress; continue;
                }
            }
            const block=this.cfg.blockByAddr.get(addr); if(!block) break;
            const term=blockTerminal(block);
            const lastInsn=block.instructions.at(-1);
            const body=this.cachedBody(addr);
            const cleanedBody=body.filter(x=>{
                if(x.kind==='assign' && x.hideTemp) return false;
                if(term?.kind==='return' && x.kind==='assign' && x.dst?.name==='x0') return false;
                return true;
            });
            out.push(...cleanedBody);
            { const live=block.successors.filter(x=>this.cfg.blockByAddr.has(x.address)); if(live.length===1) out.push(...this.edgeStmts(addr,live[0].address)); }

            if(!term) {
                const n=block.successors[0]?.address; if(n==null) break; addr=n; continue;
            }
            if(term.kind==='return') {
                const state=this.df.outState.get(addr)||newEntryState();
                const rr=this.context.returnReg || 'x0';
                out.push(stmt('return',{expr:readReg(state,rr)}));
                this.emitted.add(addr); break;
            }
            if(term.kind==='ret-indirect' || term.kind==='indirect-jump') {
                const state=this.df.outState.get(addr)||newEntryState();
                const e=readReg(state,term.reg||'x0');
                const lastI=block.instructions.at(-1);
                if(term.kind==='indirect-jump' && /^br$/i.test(lastI.mnemonic) && e && (e.kind==='load' || e.kind==='var' || e.kind==='call')) {
                    const st2=state.clone();
                    { const ti=regIndex(lastI.operands?.[0]); if(ti!=null && ti>0) st2.argWrites?.delete(ti); if(st2.argWrites instanceof Set && st2.argWrites.size===0 && (ti==null || ti>0)) { const x0=st2.regs.get('x0'); if(x0===undefined || (x0.kind==='var' && x0.name==='arg0')) st2.argWrites.add(0); } }
                    let ir=null;
                    try { ir=liftInstruction({...lastI,mnemonic:'blr',asm:String(lastI.asm||'br').replace(/^br\b/,'blr')},st2,this.context); } catch(err) { ir=null; }
                    const cs=(ir||[]).find(x=>x.kind==='call');
                    if(cs) { out.push(stmt('return',{expr:cs.expr})); break; }
                }
                out.push(stmt('indirect',{expr:e})); break;
            }
            if(term.kind==='terminal') { out.push(stmt('raw',{text:`/* ${block.instructions.at(-1).asm} */`})); break; }
            if(term.kind==='call') {
                const fall=block.successors[0]?.address; if(fall==null) break; addr=fall; continue;
            }
            if(term.kind==='jump') {
                if(this.tailCallTarget(term)) { out.push(...this.tailCall(block,addr)); break; }
                if(term.symbol) {
                        const known=this.context.functionArgCountFor?.(term.symbol,term.target) ?? null;
                        const st=this.df.outState.get(addr) || newEntryState();
                        const argc=known!=null ? known : (inferCallArgCountFromState(st,8) || this.context.currentFunctionArgCount || 0);
                        out.push(stmt('return',{expr:call(term.symbol,collectCallArgs(st,argc))}));
                    }
                else {
                    const target=term.target;
                    if(target==null) out.push(stmt('goto_indirect',{expr:unknown('branch target')}));
                    else if(target < this.cfg.entryAddress) {
                        const st=this.df.outState.get(addr) || newEntryState();
                        const name=this.context.functionNameAt?.(target) || `sub_${target.toString(16)}`;
                        const argc=(this.context.functionArgCountFor?.(name,target) ?? null);
                        const n=argc!=null ? argc : (inferCallArgCountFromState(st,8) || this.context.currentFunctionArgCount || 0);
                        out.push(stmt('return',{expr:call(name,collectCallArgs(st,n))}));
                        break;
                    }
                    else if(control?.header===target) { out.push(stmt('continue')); break; }
                    else if(control?.exit===target) { out.push(stmt('break')); break; }
                    else if(target===stop) break;
                    else if(target!==null) {
                        if(this.emitted.has(target)) out.push(stmt('goto',{target}));
                        else if(target < addr) out.push(stmt('goto',{target}));
                        else { addr=target; continue; }
                    }
                }
                break;
            }
            if(term.kind==='cond') {
                const switchInfo=this.detectSwitch(block);
                if(switchInfo) {
                    out.push(stmt('switch',switchInfo));
                    break;
                }
                const succT=block.successors.find(s=>s.type==='true');
                const succF=block.successors.find(s=>s.type==='false');
                if(!succT || !succF) {
                    out.push(stmt('ifgoto',{cond:branchCondition(lastInsn,this.df.outState.get(addr)||newEntryState()),target:succT?.address??null})); break;
                }

                const eT=this.edgeStmts(addr,succT.address), eF=this.edgeStmts(addr,succF.address);
                const canLoopT=this.reachesBackedge(succT.address,addr);
                const canLoopF=this.reachesBackedge(succF.address,addr);
                if(canLoopT !== canLoopF) {
                    const bodyAddr=canLoopT?succT.address:succF.address;
                    const exitAddr=canLoopT?succF.address:succT.address;
                    const cond0=branchCondition(lastInsn,this.df.outState.get(addr)||newEntryState());
                    const cond=canLoopT?cond0:negateExpr(cond0);
                    const loopRegion=this.collectLoop(addr,this.backPreds(block));
                    loopRegion.delete(addr);
                    const bodySt=[...(canLoopT?eT:eF),...this.buildStatements(bodyAddr,addr,loopRegion,depth+1,{header:addr,exit:exitAddr})];
                    out.push(stmt('while',{cond,body:bodySt}),...(canLoopT?eF:eT));
                    addr=exitAddr; continue;
                }

                const cexpr=branchCondition(lastInsn,this.df.outState.get(addr)||newEntryState());
                const finalT=control ? this.followTrivialJumps(succT.address) : null;
                const finalF=control ? this.followTrivialJumps(succF.address) : null;

                if(control?.header===finalT && finalF!==control.header) {
                    out.push(stmt('if',{cond:cexpr,then:[...this.pathStmts(addr,succT.address),stmt('continue')],else:[]}),...eF);
                    addr=succF.address; continue;
                }
                if(control?.header===finalF && finalT!==control.header) {
                    out.push(stmt('if',{cond:negateExpr(cexpr),then:[...this.pathStmts(addr,succF.address),stmt('continue')],else:[]}),...eT);
                    addr=succT.address; continue;
                }
                if(control?.exit===finalT && finalF!==control.exit) {
                    out.push(stmt('if',{cond:cexpr,then:[...this.pathStmts(addr,succT.address),stmt('break')],else:[]}),...eF);
                    addr=succF.address; continue;
                }
                if(control?.exit===finalF && finalT!==control.exit) {
                    out.push(stmt('if',{cond:negateExpr(cexpr),then:[...this.pathStmts(addr,succF.address),stmt('break')],else:[]}),...eT);
                    addr=succT.address; continue;
                }

                const join=this.immediateJoin(block);
                if(join==null && !this.noReturnArm(succT.address) && !this.noReturnArm(succF.address)) {
                    const thenSt=[...eT,...this.buildStatements(succT.address,stop,region,depth+1,control)];
                    const elseSt=[...eF,...this.buildStatements(succF.address,stop,region,depth+1,control)];
                    out.push(stmt('if',{cond:cexpr,then:thenSt,else:elseSt}));
                    break;
                }
                if(join!=null && join!==addr) {
                    const cond=cexpr;
                    const visitedBefore=new Set(this.visited);
                    const thenSt=[...eT,...this.buildStatements(succT.address,join,null,depth+1,control)];
                    const elseSt=[...eF,...this.buildStatements(succF.address,join,null,depth+1,control)];
                    if(!thenSt.length && !elseSt.length) { addr=join; continue; }
                    if(thenSt.some(x=>x.kind!=='label') || elseSt.some(x=>x.kind!=='label')) {
                        out.push(stmt('if',{cond,then:thenSt,else:elseSt.length?elseSt:[]}));
                        addr=join; continue;
                    }
                    this.visited=visitedBefore;
                }
                if(eT.length) out.push(stmt('if',{cond:cexpr,then:[...eT,stmt('goto',{target:succT.address})],else:[]}));
                else out.push(stmt('ifgoto',{cond:cexpr,target:succT.address}));
                out.push(...eF);
                addr=succF.address; continue;
            }
            break;
        }
        return out;
    }

    renderAST() {
        let targets=new Set(), body=[];
        for(let pass=0;pass<4;pass++) {
            this.emitted.clear(); this.structuringKeys.clear(); this.visited=new Set(); this.labelTargets=targets;
            body=this.buildStatements();
            const appended=new Set();
            for(let more=true;more;) {
                more=false;
                for(const t of collectGotoTargets(body)) {
                    if(this.stackFailTarget(t) || this.visited.has(t) || appended.has(t) || !this.cfg.blockByAddr.has(t)) continue;
                    appended.add(t);
                    body.push(...this.buildStatements(t,null,null,0,null));
                    more=true;
                }
            }
            const found=new Set([...collectGotoTargets(body)].filter(t=>!this.stackFailTarget(t)));
            if([...found].every(t=>targets.has(t))) break;
            targets=new Set([...targets,...found]);
        }
        return stmt('block',{body});
    }
}

function collectGotoTargets(list, out=new Set()) {
    for(const s of list||[]) {
        if((s.kind==='goto' || s.kind==='ifgoto') && s.target!=null) out.add(s.target);
        else if(s.kind==='block' || s.kind==='while' || s.kind==='doWhile') collectGotoTargets(s.body,out);
        else if(s.kind==='if') { collectGotoTargets(s.then,out); collectGotoTargets(s.else,out); }
        else if(s.kind==='switch') { s.cases.forEach(cs=>collectGotoTargets(cs.body,out)); collectGotoTargets(s.defaultBody,out); }
    }
    return out;
}

function printStmt(s, indent=0, lines=[]) {
    const pad='    '.repeat(indent);
    switch(s.kind) {
        case 'block': for(const x of s.body) printStmt(x,indent,lines); break;
        case 'assign': lines.push(`${pad}${printLValue(s.dst)} = ${printExpr(s.expr)};`); break;
        case 'expr': lines.push(`${pad}${printExpr(s.expr)};`); break;
        case 'return': lines.push(`${pad}return ${printExpr(s.expr)};`); break;
        case 'while':
            lines.push(`${pad}while (${printExpr(s.cond)}) {`);
            for(const x of s.body) printStmt(x,indent+1,lines);
            lines.push(`${pad}}`);
            break;
        case 'doWhile':
            lines.push(`${pad}do {`);
            for(const x of s.body) printStmt(x,indent+1,lines);
            lines.push(`${pad}} while (${printExpr(s.cond)});`);
            break;
        case 'switch':
            lines.push(`${pad}switch (${printExpr(s.expr)}) {`);
            for(const cs of s.cases) {
                lines.push(`${pad}    case ${cs.value}:`);
                for(const x of cs.body) printStmt(x,indent+2,lines);
            }
            if(s.defaultBody?.length) {
                lines.push(`${pad}    default:`);
                for(const x of s.defaultBody) printStmt(x,indent+2,lines);
            }
            lines.push(`${pad}}`);
            break;
        case 'if':
            lines.push(`${pad}if (${printExpr(s.cond)}) {`);
            for(const x of s.then) printStmt(x,indent+1,lines);
            if(s.else?.length) {
                lines.push(`${pad}} else {`);
                for(const x of s.else) printStmt(x,indent+1,lines);
            }
            lines.push(`${pad}}`);
            break;
        case 'label': lines.push(`L_${s.target.toString(16)}:`); break;
        case 'goto': lines.push(`${pad}goto L_${s.target.toString(16)};`); break;
        case 'ifgoto': lines.push(`${pad}if (${printExpr(s.cond)}) goto L_${(s.target??0).toString(16)};`); break;
        case 'break': lines.push(`${pad}break;`); break;
        case 'continue': lines.push(`${pad}continue;`); break;
        case 'goto_indirect': lines.push(`${pad}goto *${printExpr(s.expr)};`); break;
        case 'indirect': lines.push(`${pad}goto *${printExpr(s.expr)};`); break;
        case 'raw': lines.push(`${pad}${s.text}`); break;
        default: lines.push(`${pad}/* unknown statement */`);
    }
}

function printLValue(dst) {
    if(!dst) return '/*lhs*/';
    if(typeof dst==='string') return dst;
    if(dst.kind==='var' && typeof dst.name==='string' && /^&[^.]/.test(dst.name)) return dst.name.slice(1);
    return printExpr(dst);
}

function collectAssignedLocals(ast, out=new Set()) {
    if(!ast) return out;
    const visit=s=>{
        if(s.kind==='assign' && typeof s.dst?.name==='string' && /^(?:local_|tmp_obj|v_|swap_)/.test(s.dst.name)) out.add(s.dst.name);
        if(s.kind==='if'){s.then.forEach(visit);s.else.forEach(visit);}
        if(s.kind==='while' || s.kind==='doWhile')s.body.forEach(visit);
        if(s.kind==='switch'){s.cases.forEach(cs=>cs.body.forEach(visit)); s.defaultBody.forEach(visit);}
        if(s.kind==='block')s.body.forEach(visit);
    };
    visit(ast); return out;
}

function walkExprCalls(e, fn, seen=new Set()) {
    if(!e || seen.has(e.id)) return; seen.add(e.id);
    if(e.kind==='call') fn(e);
    switch(e.kind) {
        case 'unary': case 'cast': case 'bitcast': walkExprCalls(e.a,fn,seen); break;
        case 'builtin': (e.args||[]).forEach(a=>walkExprCalls(a,fn,seen)); break;
        case 'fpcond': walkExprCalls(e.lhs,fn,seen); walkExprCalls(e.rhs,fn,seen); break;
        case 'binary': walkExprCalls(e.a,fn,seen); walkExprCalls(e.b,fn,seen); break;
        case 'load': walkExprCalls(e.addr,fn,seen); break;
        case 'call': e.args.forEach(a=>walkExprCalls(a,fn,seen)); walkExprCalls(e.indirect,fn,seen); break;
        case 'select': walkExprCalls(e.cond,fn,seen); walkExprCalls(e.yes,fn,seen); walkExprCalls(e.no,fn,seen); break;
        case 'phi': e.incoming.forEach(a=>walkExprCalls(a,fn,seen)); break;
    }
}

function removeRedundantCallStatements(ast) {
    const callStmtIds=new Set(), usedCallIds=new Set(), sharedSeen=new Set();
    const scan=s=>{
        if(s.kind==='expr' && s.expr?.kind==='call') { callStmtIds.add(s.expr.id); (s.expr.args||[]).forEach(a=>walkExprCalls(a,e=>usedCallIds.add(e.id),sharedSeen)); walkExprCalls(s.expr.indirect,e=>usedCallIds.add(e.id),sharedSeen); }
        else if(s.kind==='ifgoto') walkExprCalls(s.cond,e=>usedCallIds.add(e.id),sharedSeen);
        else if(s.kind==='indirect' || s.kind==='goto_indirect') walkExprCalls(s.expr,e=>usedCallIds.add(e.id),sharedSeen);
        else if(s.kind==='doWhile'){walkExprCalls(s.cond,e=>usedCallIds.add(e.id),sharedSeen);s.body.forEach(scan);}
        else if(s.kind==='assign') walkExprCalls(s.expr,e=>usedCallIds.add(e.id),sharedSeen);
        else if(s.kind==='return') walkExprCalls(s.expr,e=>usedCallIds.add(e.id),sharedSeen);
        else if(s.kind==='if'){walkExprCalls(s.cond,e=>usedCallIds.add(e.id),sharedSeen);s.then.forEach(scan);s.else.forEach(scan);}
        else if(s.kind==='while'){walkExprCalls(s.cond,e=>usedCallIds.add(e.id),sharedSeen);s.body.forEach(scan);}
        else if(s.kind==='switch'){walkExprCalls(s.expr,e=>usedCallIds.add(e.id),sharedSeen);s.cases.forEach(cs=>cs.body.forEach(scan));s.defaultBody.forEach(scan);}
        else if(s.kind==='block') s.body.forEach(scan);
    };
    scan(ast);
    const pruneList=list=>list.filter(x=>!(x.kind==='expr'&&x.expr?.kind==='call'&&usedCallIds.has(x.expr.id))).map(x=>{prune(x);return x;});
    const prune=s=>{
        if(s.kind==='block') s.body=pruneList(s.body);
        else if(s.kind==='if'){s.then=pruneList(s.then);s.else=pruneList(s.else);}
        else if(s.kind==='while' || s.kind==='doWhile')s.body=pruneList(s.body);
        else if(s.kind==='switch'){s.cases.forEach(cs=>cs.body=pruneList(cs.body));s.defaultBody=pruneList(s.defaultBody);}
    };
    prune(ast); return ast;
}

function rewriteStackProtectorIfGotos(ast, cfg, image) {
    if(!ast || !cfg?.blockByAddr) return ast;
    const rewrite=list=>{
        const out=[];
        for(const s of list||[]) {
            if(s.kind==='ifgoto' && s.target!=null) {
                const b=cfg.blockByAddr.get(s.target);
                const first=b?.instructions?.[0];
                const target=first ? directTarget(first) : null;
                const name=first?.relocation?.symbol || (target!=null ? image?.codeSymbolAt?.(target) : null);
                if(first?.mnemonic==='bl' && name && /stack_chk_fail/.test(name)) {
                    out.push(stmt('if',{cond:s.cond,then:[stmt('expr',{expr:call(name,[])})],else:[]}));
                    continue;
                }
            }
            if(s.kind==='block') s.body=rewrite(s.body);
            else if(s.kind==='if') { s.then=rewrite(s.then); s.else=rewrite(s.else); }
            else if(s.kind==='while'||s.kind==='doWhile') s.body=rewrite(s.body);
            else if(s.kind==='switch') { for(const cs of s.cases) cs.body=rewrite(cs.body); s.defaultBody=rewrite(s.defaultBody); }
            out.push(s);
        }
        return out;
    };
    if(ast.kind==='block') ast.body=rewrite(ast.body);
    return ast;
}

function demangleName(n) {
    n = String(n || '');
    if (!n.startsWith('_Z')) return n;
    let i = 2;
    const parts = [];
    const ident = () => {
        let j = i; while (j < n.length && n.charCodeAt(j) >= 48 && n.charCodeAt(j) <= 57) j++;
        if (j === i) return null;
        const len = Number(n.slice(i, j));
        if (!len || j + len > n.length) return null;
        const id = n.slice(j, j + len); i = j + len; return id;
    };
    if (n[i] === 'N') {
        i++;
        while (i < n.length && 'rVK'.includes(n[i])) i++;
        for (;;) {
            if (n[i] === 'E') break;
            if (n[i] === 'C' || n[i] === 'D') { const prev = parts[parts.length - 1]; if (!prev) return n; parts.push(n[i] === 'D' ? '~' + prev : prev); i += 2; continue; }
            const id = ident();
            if (id === null) return n;
            parts.push(id);
        }
    } else {
        const id = ident();
        if (id === null) return n;
        parts.push(id);
    }
    if (parts.length > 1 && /^h[0-9a-f]{16}$/.test(parts[parts.length - 1])) parts.pop();
    return parts.join('::');
}

function dropStackGuard(ast) {
    const isGuard=e=>{ while(e && e.kind==='load') e=e.addr; return !!e && e.kind==='var' && /^&?__stack_chk_guard$/.test(e.name||''); };
    let any=false;
    const scan=list=>{ for(const s of list||[]) { if(s.kind==='assign' && isGuard(s.expr)) any=true; for(const k of ['then','else','body']) if(Array.isArray(s[k])) scan(s[k]); if(s.cases) s.cases.forEach(cs=>scan(cs.body)); if(s.defaultBody) scan(s.defaultBody); } };
    const root=Array.isArray(ast)?ast:ast?.body;
    scan(root);
    if(!any) return ast;
    const rewrite=list=>{
        const out=[];
        for(const s of list||[]) {
            if(s.kind==='assign' && isGuard(s.expr)) continue;
            if(s.kind==='if' && s.cond?.kind==='binary' && (s.cond.op==='!=' || s.cond.op==='==') && (isGuard(s.cond.a) || isGuard(s.cond.b))) {
                const keep=s.cond.op==='!=' ? s.else : s.then;
                out.push(...rewrite(keep));
                continue;
            }
            for(const k of ['then','else','body']) if(Array.isArray(s[k])) s[k]=rewrite(s[k]);
            if(s.cases) for(const cs of s.cases) cs.body=rewrite(cs.body);
            if(s.defaultBody) s.defaultBody=rewrite(s.defaultBody);
            out.push(s);
        }
        return out;
    };
    if(Array.isArray(ast)) return rewrite(ast);
    ast.body=rewrite(ast.body);
    return ast;
}

function normalizeASTBeforePrint(ast, cfg, image) {
    if(!ast) return ast;
    const rewrite=list=>{
        const out=[];
        for(const s of list||[]) {
            if(s.kind==='ifgoto' && s.target!=null) {
                const b=cfg?.blockByAddr?.get(s.target);
                const first=b?.instructions?.[0];
                const target=first ? directTarget(first) : null;
                const name=first?.relocation?.symbol || (target!=null ? image?.codeSymbolAt?.(target) : null);
                if(first?.mnemonic==='bl' && name && /stack_chk_fail/.test(name)) {
                    out.push(stmt('if',{cond:s.cond,then:[stmt('expr',{expr:call(name,[])})],else:[]}));
                    continue;
                }
            }
            if(s.kind==='block') {
                s.body=rewrite(s.body);
            } else if(s.kind==='if') {
                s.then=rewrite(s.then); s.else=rewrite(s.else);
            } else if(s.kind==='while'||s.kind==='doWhile') {
                s.body=rewrite(s.body);
            } else if(s.kind==='switch') {
                for(const cs of s.cases) cs.body=rewrite(cs.body);
                s.defaultBody=rewrite(s.defaultBody);
            }
            if(s.kind==='if' && !s.then.length && !s.else.length) continue;
            out.push(s);
        }
        return out;
    };
    if(ast.kind==='block') ast.body=rewrite(ast.body);
    return ast;
}

function cleanupAST(ast, options={}) {
    rewriteStackProtectorIfGotos(ast, options.cfg, options.image);
    const clean=s=>{
        if(s.kind==='block') s.body=s.body.flatMap(clean);
        if(s.kind==='if'){s.then=s.then.flatMap(clean);s.else=s.else.flatMap(clean); if(!s.then.length && !s.else.length) return []; }
        if(s.kind==='switch'){
            for(const cs of s.cases) cs.body=cs.body.flatMap(clean);
            s.defaultBody=s.defaultBody.flatMap(clean);
        }
        if(s.kind==='while' || s.kind==='doWhile'){
            s.body=s.body.flatMap(clean);
            if(s.body.at(-1)?.kind==='continue') s.body.pop();
        }
        if(s.kind==='assign' && s.hideTemp) return [];
        return [s];
    };
    const out=clean(ast)[0] || stmt('block',{body:[]});
    const optimize=s=>{
        if(!s) return s;
        if(s.kind==='block') s.body=s.body.map(optimize).filter(Boolean);
        else if(s.kind==='if') {
            s.then=s.then.map(optimize).filter(Boolean); s.else=s.else.map(optimize).filter(Boolean);
            if(!s.then.length && !s.else.length) return null;

            if(!s.else.length && s.then.length===1 && s.then[0].kind==='doWhile' &&
               exprEq(s.cond,s.then[0].cond)) return stmt('while',{cond:s.cond,body:s.then[0].body});
            if(!s.then.length && s.else.length){const t=s.then;s.then=s.else;s.else=t;s.cond=negateExpr(s.cond);}
            if(s.then.length===1&&s.then[0].kind==='return'&&s.else.length===1&&s.else[0].kind==='return') return stmt('return',{expr:simplifyExpr(select(s.cond,s.then[0].expr,s.else[0].expr))});
        } else if(s.kind==='while'||s.kind==='doWhile') s.body=s.body.map(optimize).filter(Boolean);
        else if(s.kind==='switch'){s.cases.forEach(cs=>cs.body=cs.body.map(optimize).filter(Boolean));s.defaultBody=s.defaultBody.map(optimize).filter(Boolean);}
        return s;
    };
    return removeRedundantCallStatements(optimize(out));
}

function functionHeader(name, argCount=0, fpArgCount=0) {
    const args=[];
    for(let i=0;i<argCount;i++) args.push(`arg${i}`);
    for(let i=0;i<fpArgCount;i++) args.push(`farg${i}`);
    return `function ${name}(${args.join(', ')}) {`;
}

function mergeTypeHint(current,next){
    if(!next) return current||null;
    if(!current) return next;
    if(current===next) return current;
    if(current==='void *'||next==='void *') return 'void *';
    if((current==='float'||current==='double')&&(next==='float'||next==='double')) return current==='double'||next==='double'?'double':'float';
    if((current==='int32_t'||current==='uint32_t')&&(next==='int32_t'||next==='uint32_t')) return current==='uint32_t'&&next==='uint32_t'?'uint32_t':'int32_t';
    return 'int64_t';
}

function inferFunctionArgTypes(cfg){
    const types=Array.from({length:8},()=>null);
    const mark=(n,t)=>{if(n>=0&&n<8)types[n]=mergeTypeHint(types[n],t);};
    for(const insn of cfg.instructions){
        for(const op of insn.operands||[]){
            const r=regNorm(op); let m=r.match(/^([wx])(\d+)$/i);
            if(m){const n=Number(m[2]);if(n<8)mark(n,m[1].toLowerCase()==='w'?'int32_t':'int64_t');}
            m=r.match(/^([ds])(\d+)$/i);
            if(m){const n=Number(m[2]);if(n<8)mark(n,m[1].toLowerCase()==='s'?'float':'double');}
            const mem=parseMem(op); if(mem){const b=regIndex(mem.base);if(b!=null&&b<8)mark(b,'void *');}
        }
    }
    return types.map(t=>t||'int64_t');
}

function inferFunctionReturnType(cfg){
    for(let i=cfg.instructions.length-1;i>=0;i--){
        const insn=cfg.instructions[i],d=instructionRegDest(insn);
        if(d==='x0') return /^w0$/i.test(insn.operands?.[0]||'')?'int32_t':'int64_t';
        if(/^s0$/i.test(d||'')) return 'float';
        if(/^d0$/i.test(d||'')) return 'double';
    }
    return 'int64_t';
}

function rodataTables(ast, image) {
    const found=new Map(), seen=new Set();
    const visit=e=>{
        if(!e || seen.has(e.id)) return; seen.add(e.id);
        if(e.kind==='load') { const ar=arrayAccess(e); if(ar && !found.has(ar.name)) found.set(ar.name,{bytes:ar.bytes,signed:!!e.signed}); }
        if(e.kind==='phi') { for(const x of e.incoming.values()) visit(x); return; }
        for(const ch of exprChildren(e)) visit(ch);
    };
    for(const e of collectAstExprs({kind:'block',body:Array.isArray(ast)?ast:[ast]},[])) visit(e);
    const out=[];
    for(const [name,info] of found) {
        const addr=parseInt(name.slice(7),16), sec=image.sectionContaining(addr);
        if(!sec) continue;
        const n=Math.min(8,Math.floor((sec.addr+sec.size-addr)/info.bytes)), vals=[];
        for(let i=0;i<n;i++) {
            const b=image.readVM(addr+i*info.bytes,info.bytes); if(!b) break;
            let v= info.bytes===1 ? b[0] : info.bytes===2 ? b.readUInt16LE(0) : info.bytes===4 ? b.readUInt32LE(0) : Number(b.readBigUInt64LE(0));
            if(info.signed || info.bytes===4) { const bits=info.bytes*8; if(bits<64 && v>=2**(bits-1)) v-=2**bits; }
            vals.push(v);
        }
        out.push(`${name}: int${info.bytes*8}_t[] = {${vals.join(', ')}${n>=8?', ...':''}}  (first ${vals.length})`);
    }
    return out;
}

function loadBase(e) {
    const a = e?.addr; if (!a) return null;
    const peel = x => { while (x && (x.kind === 'cast' || x.kind === 'bitcast')) x = x.a; return x; };
    const nameOf = x => {
        x = peel(x); if (!x) return null;
        if (x.kind === 'var' && typeof x.name === 'string' && /^[A-Za-z_][\w]*$/.test(x.name)) return x.name;
        if (x.kind === 'phi' && x.varName) return x.varName;
        return null;
    };
    let n = nameOf(a); if (n) return { name: n, k: 0 };
    if (a.kind === 'binary' && (a.op === '+' || a.op === '-') && peel(a.b)?.kind === 'const') {
        n = nameOf(a.a); if (n) return { name: n, k: a.op === '+' ? peel(a.b).value : -peel(a.b).value };
    }
    return null;
}

function forEachExpr(ast, fn) {
    const seen = new Set();
    const visit = e => {
        if (!e || seen.has(e.id)) return; seen.add(e.id);
        fn(e);
        if (e.kind === 'phi') { for (const x of e.incoming.values()) visit(x); return; }
        for (const ch of exprChildren(e)) visit(ch);
    };
    for (const e of collectAstExprs({ kind: 'block', body: Array.isArray(ast) ? ast : [ast] }, [])) visit(e);
}

function structBases(ast) {
    const offs = new Map();
    forEachExpr(ast, e => {
        if (e.kind !== 'load' || e.width === 128) return;
        const lb = loadBase(e);
        if (lb && lb.k >= 0) { if (!offs.has(lb.name)) offs.set(lb.name, new Set()); offs.get(lb.name).add(lb.k); }
    });
    const out = new Map();
    for (const [n, set] of offs) if (set.size >= 2 && Math.max(...set) >= 8) out.set(n, set);
    return out;
}

function inferCTypes(ast) {
    const ptr = new Set(), str = new Set(), copies = [];
    forEachExpr(ast, e => {
        if (e.kind !== 'load') return;
        const lb = loadBase(e); if (lb) ptr.add(lb.name);
        const mo = memberOffsetAccess(e.addr);
        if (mo) { let b = mo.base; while (b && (b.kind === 'cast' || b.kind === 'bitcast')) b = b.a; const n = b?.kind === 'var' ? b.name : b?.kind === 'phi' ? b.varName : null; if (n) ptr.add(n); }
    });
    const walkStmts = list => { for (const st of list || []) {
        if (st.kind === 'assign' && st.dst?.kind === 'var') {
            let x = st.expr; while (x && (x.kind === 'cast' || x.kind === 'bitcast')) x = x.a;
            const src = !x ? null : x.kind === 'var' ? x.name : x.kind === 'phi' ? x.varName
                : (x.kind === 'binary' && (x.op === '+' || x.op === '-') && x.b?.kind === 'const' && x.a?.kind === 'var') ? x.a.name : null;
            if (src) copies.push([st.dst.name, src]);
            if (['string', 'cfstring', 'selector'].includes(st.expr?.kind)) str.add(st.dst.name);
        }
        walkStmts(st.then); walkStmts(st.else); walkStmts(st.body); (st.cases || []).forEach(cs => walkStmts(cs.body)); walkStmts(st.defaultBody);
    } };
    walkStmts(Array.isArray(ast) ? ast : [ast]);
    for (let changed = true, n = 0; changed && n++ < 8;) {
        changed = false;
        for (const [d, sname] of copies) {
            if (ptr.has(d) && !ptr.has(sname)) { ptr.add(sname); changed = true; }
            if (ptr.has(sname) && !ptr.has(d)) { ptr.add(d); changed = true; }
            if (str.has(sname) && !str.has(d)) { str.add(d); changed = true; }
        }
    }
    const typeOf = name => /^v_[dsq]\d+_\d+$/.test(name) ? 'uint128_t' : str.has(name) ? 'const char *' : ptr.has(name) ? 'void *' : (/^farg\d+$/.test(name) ? 'double' : 'int64_t');
    let returnsValue = false, retType = 'int64_t';
    const scanRet = list => { for (const st of list || []) {
        if (st.kind === 'return' && st.expr) {
            returnsValue = true;
            const x = st.expr;
            if (['string', 'cfstring'].includes(x.kind)) retType = 'const char *';
            else if (x.kind === 'var' && ptr.has(x.name)) retType = 'void *';
            else {
                const ft = x.fpType || ((x.kind === 'cast' && (x.type === 'double' || x.type === 'float')) ? x.type : null) || (x.kind === 'const' && x.isFloat ? (x.floatType || 'double') : null);
                if (ft) retType = ft;
            }
        }
        scanRet(st.then); scanRet(st.else); scanRet(st.body); (st.cases || []).forEach(cs => scanRet(cs.body)); scanRet(st.defaultBody);
    } };
    scanRet(Array.isArray(ast) ? ast : [ast]);
    return { typeOf, returnType: returnsValue ? retType : 'void' };
}

function renderFunction(result) {
    const ast=dropStackGuard(normalizeASTBeforePrint(cleanupAST(result.ast,{cfg:result.cfg,image:result.image}),result.cfg,result.image));
    STRUCT_BASES=structBases(ast);
    const ty=inferCTypes(ast);
    const body=[];
    printStmt(ast,1,body);
    const bodyText=body.join('\n');
    let argCount=result.argCount||0, fpArgCount=result.fpArgCount||0;
    for(const m of bodyText.matchAll(/\barg(\d+)\b/g)) argCount=Math.max(argCount,Number(m[1])+1);
    for(const m of bodyText.matchAll(/\bfarg(\d+)\b/g)) fpArgCount=Math.max(fpArgCount,Number(m[1])+1);
    const lines=[];
    if(PRINT_TYPES) {
        const ps=[];
        for(let i=0;i<argCount;i++) ps.push(`${ty.typeOf(`arg${i}`)}${ty.typeOf(`arg${i}`).endsWith('*')?'':' '}arg${i}`);
        for(let i=0;i<fpArgCount;i++) ps.push(`double farg${i}`);
        lines.push(`${ty.returnType} ${demangleName(result.name)}(${ps.length?ps.join(', '):'void'}) {`);
    } else lines.push(functionHeader(result.name,argCount,fpArgCount));
    if(result.typed){
        const args=[];
        for(let i=0;i<argCount;i++) args.push(`${result.argTypes?.[i]||'int64_t'} arg${i}`);
        for(let i=0;i<fpArgCount;i++) args.push(`${result.argTypes?.[8+i]||'double'} farg${i}`);
        lines.push(`    /* signature: ${result.returnType||'int64_t'} ${result.name}(${args.join(', ')}) */`);
    }
    for(const t of rodataTables(ast,result.image)) lines.push(`    /* ${t} */`);
    const assigned=collectAssignedLocals(ast);
    const extra=new Set();
    for(const m of bodyText.matchAll(/\blocal_m\d+\b/g)) if(!assigned.has(m[0])) extra.add(m[0]);
    const locals=[...new Set([...assigned,...extra])].sort((a,b)=>a.localeCompare(b,undefined,{numeric:true}));
    if(locals.length) {
        if(PRINT_TYPES) {
            const groups=new Map();
            for(const n of locals) { const t=extra.has(n) ? 'int64_t' : ty.typeOf(n); if(!groups.has(t)) groups.set(t,[]); groups.get(t).push(n); }
            for(const [t,ns] of groups) { const ptr=t.endsWith('*'); lines.push(ptr ? `    ${t.replace(/ \*$/,'')} ${ns.map(n=>'*'+n).join(', ')};` : `    ${t} ${ns.join(', ')};`); }
        } else lines.push(`    /* locals: ${locals.join(', ')} */`);
    }
    lines.push(...body);
    lines.push('}');
    return lines.join('\n');
}

function instructionRegDest(insn) {
    const m=insn.mnemonic, o=insn.operands;
    if(!o.length) return null;
    if(['cmp','cmn','tst','ccmp','ccmn','fcmp','fcmpe','fccmp','fccmpe','str','strb','strh','stur','sturb','sturh','stp','stnp','ret','br','blr','braa','brab','braaz','brabz','b','bl','cbz','cbnz','tbz','tbnz'].includes(m) || isCondBranch(m)) return null;
    return isRegister(o[0]) && !isSP(o[0]) ? canonicalReg(o[0]) : null;
}

function instructionExtraDest(insn) {
    const m=insn.mnemonic;
    if((m==='ldp' || m==='ldnp' || m==='ldpsw') && isRegister(insn.operands[1]) && !isSP(insn.operands[1])) return canonicalReg(insn.operands[1]);
    return null;
}

function instructionSourceRegs(insn) {
    const m=insn.mnemonic, o=insn.operands, regs=[];
    const addRegs=(text)=>{
        const re=/(?:^|[^a-z0-9_])((?:(?:x|w)(?:[0-9]|[12][0-9]|30)|(?:v|q|d|s|h|b)(?:[0-9]|[12][0-9]|3[01])))(?:$|[^a-z0-9_])/gi;
        let mm; while((mm=re.exec(String(text)))!==null) regs.push(canonicalReg(mm[1]));
    };
    if(m==='ldp' || m==='ldnp' || m==='ldpsw') { addRegs(o[2]); return regs; }
    if(m.startsWith('stp') || m==='stnp') { addRegs(o[0]); addRegs(o[1]); addRegs(o[2]); return regs; }
    if(['fcmp','fcmpe','fccmp','fccmpe'].includes(m)) { o.forEach(addRegs); return regs; }
    if(m.startsWith('str') || m.startsWith('stur')) { addRegs(o[0]); addRegs(o[1]); return regs; }
    if(['cmp','cmn','tst','ccmp','ccmn'].includes(m)) { o.forEach(addRegs); return regs; }
    if(['cbz','cbnz','tbz','tbnz'].includes(m)) { addRegs(o[0]); return regs; }
    if(['ret','br','blr','braa','brab','braaz','brabz'].includes(m)) { addRegs(o[0]); return regs; }
    if(m==='bl' || m==='b' || isCondBranch(m)) return regs;
    const d=instructionRegDest(insn);
    for(let i=d?1:0;i<o.length;i++) addRegs(o[i]);
    return regs;
}

function inferFunctionFPArgCount(cfg) {
    const defined=new Set(), used=new Set();
    for(const insn of cfg.instructions) {
        for(const r of instructionSourceRegs(insn)) {
            const m=/^[ds]([0-9]+)$/i.exec(r);
            if(m) { const n=Number(m[1]); if(n<8 && !defined.has(r)) used.add(n); }
        }
        const d=instructionRegDest(insn);
        if(d && /^[ds][0-9]+$/i.test(d)) defined.add(d);
        const d2=instructionExtraDest(insn);
        if(d2 && /^[ds][0-9]+$/i.test(d2)) defined.add(d2);
    }
    return used.size ? Math.max(...used)+1 : 0;
}

function inferFunctionReturnRegister(cfg) {
    for(let i=cfg.instructions.length-1;i>=0;i--) {
        const insn=cfg.instructions[i];
        if(insn.mnemonic==='ret' || insn.mnemonic==='retaa' || insn.mnemonic==='retab') continue;
        const d=instructionRegDest(insn);
        if(d==='x0') return 'x0';
        if(/^(?:d|s)0$/i.test(d||'')) return d;
    }
    return 'x0';
}

function liveInArgRegs(cfg, callArgc = () => 0) {
    const use = new Map(), def = new Map();
    for (const b of cfg.blocks) {
        const u = new Set(), d = new Set();
        for (const insn of b.instructions) {
            const srcs = [...instructionSourceRegs(insn)];
            if (insn.mnemonic === 'bl' || insn.mnemonic === 'blr') for (let i = 0, n = callArgc(insn); i < n; i++) srcs.push(`x${i}`);
            for (const r of srcs) { const n = regIndex(r); if (n != null && n < 8 && !d.has(`x${n}`)) u.add(`x${n}`); }
            const w = instructionRegDest(insn); if (w) { const n = regIndex(w); d.add(n != null ? `x${n}` : w); }
            const w2 = instructionExtraDest(insn); if (w2) { const n = regIndex(w2); d.add(n != null ? `x${n}` : w2); }
            if (insn.mnemonic === 'bl' || insn.mnemonic === 'blr') for (let i = 0; i <= 17; i++) d.add(`x${i}`);
        }
        use.set(b.address, u); def.set(b.address, d);
    }
    const liveIn = new Map(cfg.blocks.map(b => [b.address, new Set(use.get(b.address))]));
    for (let changed = true; changed;) {
        changed = false;
        for (const b of cfg.blocks) {
            const cur = liveIn.get(b.address), d = def.get(b.address);
            for (const sc of b.successors) {
                const si = liveIn.get(sc.address); if (!si) continue;
                for (const r of si) if (!d.has(r) && !cur.has(r)) { cur.add(r); changed = true; }
            }
        }
    }
    return liveIn.get(cfg.entryAddress) || new Set();
}

function inferFunctionArgCount(cfg) {
    const live = liveInArgRegs(cfg);
    return live.size ? Math.max(...[...live].map(r => regIndex(r))) + 1 : 0;
}

function inferFunctionArgCountWithCalls(fn, funcsByName, funcsByAddr, image, symbolArgCounts=new Map()) {
    const callArgc = insn => {
        if (insn.mnemonic !== 'bl') return 0;
        const target = directTarget(insn);
        const name = insn.relocation?.symbol || (target != null ? image.functionNameAt(target) : null);
        const callee = (target != null ? funcsByAddr.get(target) : null) || (name ? funcsByName.get(name) : null);
        return callee?.argCount ?? ((target != null ? symbolArgCounts.get(target) : null) ?? (name ? symbolArgCounts.get(name) : null)) ?? 0;
    };
    const live = liveInArgRegs(fn.cfg, callArgc);
    return live.size ? Math.max(...[...live].map(r => regIndex(r))) + 1 : fn.argCount || 0;
}

function plausibleCallTarget(target, image) {
    return target != null && target >= image.getTextStart() && target < image.getTextEnd() && (target & 3) === 0;
}

function nameThunks(image, functions) {
    const allowed=new Set(['nop','adr','adrp','add','ldr','mov','movz','movk']);
    for(const f of functions) {
        if(!/^sub_[0-9a-f]+$/.test(f.name)) continue;
        const ins=f.cfg.instructions;
        if(!ins.length || ins.length>8) continue;
        const last=ins[ins.length-1];
        if(last.mnemonic!=='b' || !ins.slice(0,-1).every(i=>allowed.has(i.mnemonic))) continue;
        const target=directTarget(last);
        const callee=last.relocation?.symbol || (target!=null ? image.codeSymbolAt(target) : null);
        if(!callee || /^sub_[0-9a-f]+$/.test(callee)) continue;
        const ref=collectStringRefs(image,f).find(r=>/^[A-Za-z_][A-Za-z0-9_$.:]*$/.test(r.text));
        if(!ref) continue;
        const sym=image.meta.functionSymbols.find(x=>x.value===f.start);
        const ident=ref.text.replace(/[^A-Za-z0-9_]/g,'_').replace(/_+$/,'');
        if(sym) { image.renameFunctionSymbol(sym,`${callee}$${ident}`,'thunk'); f.name=sym.name; }
        else f.name=`${callee}$${ident}`;
    }
}

function discoverFunctions(image, decoder, options={}) {
    const all=image.allWords(decoder);
    const byAddr=new Map(all.map(i=>[i.address,i]));
    const textStart=image.getTextStart();
    const slice=(a,b)=>all.slice(Math.max(0,Math.ceil((a-textStart)/4)),Math.max(0,Math.ceil((b-textStart)/4)));
    const entries=new Map();
    image.functionNameAt(-1);
    const symByName=new Map();
    for(const s of image.meta.functionSymbols) if(!symByName.has(s.name)) symByName.set(s.name,s);
    if(options.includeAllSymbols) {
        for(const s of image.getFunctionSymbols()) {
            if(s.value>=image.getTextStart() && s.value<image.getTextEnd()) entries.set(s.value,s.name);
        }
    }
    const requested=options.entries?.length?options.entries:[image.meta.functionSymbols[0]?.value ?? options.entry ?? image.getTextStart()];
    for(const e of requested) if(e!=null) entries.set(Number(e), image.functionNameAt(Number(e)) || `sub_${Number(e).toString(16)}`);

    const queue=[...entries.keys()]; const seen=new Set(); const functions=[];
    while(queue.length) {
        const start=queue.shift(); if(seen.has(start)) continue; seen.add(start);
        if(!byAddr.has(start)) continue;
        const [rangeStart,rangeEnd]=image.functionRange(start);
        const insns=slice(rangeStart,rangeEnd);
        const sym=image._fnByValue.get(start);
        const nextSym=image.nextFunctionSymbol(start);
        const boundedFunction=!!(sym && (sym.size>0 || nextSym));
        const cfg=buildCFG(insns,start,{linearAfterIndirect:boundedFunction});
        const name=entries.get(start) || image.functionNameAt(start) || `sub_${Number(start).toString(16)}`;
        const calls=[];
        for(const i of cfg.instructions) {
            const bi=branchInfo(i);
            if(i.mnemonic==='bl' || (i.mnemonic==='b' && (i.relocation?.symbol || (bi?.target!=null && bi.target<start)))) {
                const target=directTarget(i);
                const sym=i.relocation?.symbol || (target!=null?image.codeSymbolAt(target):null);
                const rawPlaceholderCall=image.meta.kind==='raw' && i.mnemonic==='bl' && target===i.address && !sym;
                if((plausibleCallTarget(target,image) || sym) && !rawPlaceholderCall) {
                    calls.push({address:i.address,target,symbol:sym,tailcall:i.mnemonic==='b'});
                    const symTarget = sym ? symByName.get(sym)?.value : null;
                    const nextTarget = target != null ? target : symTarget;
                    if(options.recursive!==false && nextTarget!=null && plausibleCallTarget(nextTarget,image) && nextTarget!==i.address && !seen.has(nextTarget)) {
                        entries.set(nextTarget,image.functionNameAt(nextTarget)||sym||`sub_${nextTarget.toString(16)}`); queue.push(nextTarget);
                    }
                }
            }
        }
        const derivedEnd=cfg.instructions.length ? Math.max(...cfg.instructions.map(i=>i.address))+4 : rangeEnd;
        const end=(sym && sym.size>0) ? rangeEnd : Math.min(rangeEnd,derivedEnd);
        functions.push({start,name,end,cfg,calls,argCount:inferFunctionArgCount(cfg),fpArgCount:inferFunctionFPArgCount(cfg),returnReg:inferFunctionReturnRegister(cfg)});
    }
    functions.sort((a,b)=>a.start-b.start);

    if(image.meta.kind==='raw' && functions.length>1) {
        for(let i=0;i<functions.length;i++) {
            const f=functions[i], next=functions[i+1]?.start??image.getTextEnd();
            const region=slice(f.start,next);
            if(region.length) { f.cfg=buildCFG(region,f.start,{linearAfterIndirect:false}); f.end=next; }
        }
    }
    nameThunks(image,functions);
    const byAddrFn=new Map(functions.map(f=>[f.start,f]));
    const byNameFn=new Map(functions.map(f=>[f.name,f]));
    const symbolArgCounts=new Map();
    const needed=new Set();
    for(const f of functions) for(const cl of f.calls) { if(cl.target!=null) needed.add(cl.target); if(cl.symbol) needed.add(cl.symbol); }
    for(const s of image.meta.functionSymbols || []) {
        if(!byAddr.has(s.value) || symbolArgCounts.has(s.value)) continue;
        if(!needed.has(s.value) && !needed.has(s.name)) continue;
        try {
            const [rs,re]=image.functionRange(s.value);
            const region=slice(rs,re);
            if(!region.length) continue;
            const next=image.nextFunctionSymbol(s.value);
            const bounded=!!(s.size>0 || next);
            const scfg=buildCFG(region,s.value,{linearAfterIndirect:bounded});
            const ac=inferFunctionArgCount(scfg);
            symbolArgCounts.set(s.value,ac);
            if(s.name) symbolArgCounts.set(s.name,ac);
        } catch(_) {}
    }
    for(let iter=0;iter<4;iter++) {
        let changed=false;
        for(const f of functions) {
            const next=inferFunctionArgCountWithCalls(f,byNameFn,byAddrFn,image,symbolArgCounts);
            if(next!==f.argCount) { f.argCount=next; changed=true; }
        }
        if(!changed) break;
    }
    const callGraph=markRecursiveFunctions(functions);
    return {all,functions,entries,callGraph};
}

function markRecursiveFunctions(functions) {
    const byAddr=new Map(functions.map(f=>[f.start,f]));
    const byName=new Map(functions.map(f=>[f.name,f]));
    const graph=new Map(functions.map(f=>[f.start,[]]));
    for(const f of functions) for(const c of f.calls||[]) {
        const target=c.target??byName.get(c.symbol)?.start;
        if(target!=null&&byAddr.has(target)) graph.get(f.start).push(target);
    }
    let index=0; const idx=new Map(),low=new Map(),stack=[],onStack=new Set(),components=[];
    const visit=vtx=>{
        idx.set(vtx,index);low.set(vtx,index++);stack.push(vtx);onStack.add(vtx);
        for(const w of graph.get(vtx)||[]) {
            if(!idx.has(w)){visit(w);low.set(vtx,Math.min(low.get(vtx),low.get(w)));}
            else if(onStack.has(w)) low.set(vtx,Math.min(low.get(vtx),idx.get(w)));
        }
        if(low.get(vtx)===idx.get(vtx)){const comp=[];let w;do{w=stack.pop();onStack.delete(w);comp.push(w);}while(w!==vtx);components.push(comp);}
    };
    for(const f of functions) if(!idx.has(f.start)) visit(f.start);
    for(const comp of components){const recursive=comp.length>1||(comp.length===1&&(graph.get(comp[0])||[]).includes(comp[0]));for(const a of comp){const f=byAddr.get(a);if(f)f.recursive=recursive;}}
    return {graph,components};
}

function summarizeSSA(ssa) {
    if(!ssa) return null;
    const phi={}; for(const [addr,nodes] of ssa.phiNodes){const xs=Object.entries(nodes).map(([reg,n])=>({reg,version:n.version,incoming:n.incoming}));if(xs.length)phi[addr]=xs;}
    const defs={},uses={}; for(const [addr,x] of ssa.renamedDefs)defs[addr]=x; for(const [addr,x] of ssa.renamedUses)uses[addr]=x;
    return {phi,defs,uses,idom:Object.fromEntries([...ssa.idom].map(([k,v])=>[k,v]))};
}

function exprChildren(e) {
    switch(e.kind) {
        case 'unary': case 'cast': case 'bitcast': return [e.a];
        case 'builtin': return e.args||[];
        case 'fpcond': return [e.lhs,e.rhs];
        case 'binary': return [e.a,e.b];
        case 'load': return [e.addr];
        case 'call': return [...(e.args||[]),e.indirect].filter(Boolean);
        case 'select': return [e.cond,e.yes,e.no];
        default: return [];
    }
}

function mapExprChildren(e, fn) {
    const m=x=>x?fn(x):x;
    switch(e.kind) {
        case 'unary': case 'cast': case 'bitcast': return {...e,id:nextExprId++,a:m(e.a)};
        case 'builtin': return {...e,id:nextExprId++,args:(e.args||[]).map(m)};
        case 'fpcond': return {...e,id:nextExprId++,lhs:m(e.lhs),rhs:m(e.rhs)};
        case 'binary': return {...e,id:nextExprId++,a:m(e.a),b:m(e.b)};
        case 'load': return {...e,id:nextExprId++,addr:m(e.addr)};
        case 'call': return {...e,id:nextExprId++,args:(e.args||[]).map(m),indirect:m(e.indirect)};
        case 'select': return {...e,id:nextExprId++,cond:m(e.cond),yes:m(e.yes),no:m(e.no)};
        default: return e;
    }
}

function collectAstExprs(s, out) {
    if(!s) return out;
    const dst=(s.dst && typeof s.dst==='object') ? s.dst : null;
    switch(s.kind) {
        case 'assign': out.push(s.expr); if(dst) out.push(dst); break;
        case 'expr': case 'return': case 'indirect': case 'goto_indirect': out.push(s.expr); break;
        case 'ifgoto': out.push(s.cond); break;
        case 'if': out.push(s.cond); (s.then||[]).forEach(x=>collectAstExprs(x,out)); (s.else||[]).forEach(x=>collectAstExprs(x,out)); break;
        case 'while': case 'doWhile': out.push(s.cond); (s.body||[]).forEach(x=>collectAstExprs(x,out)); break;
        case 'switch': out.push(s.expr); (s.cases||[]).forEach(cs=>(cs.body||[]).forEach(x=>collectAstExprs(x,out))); (s.defaultBody||[]).forEach(x=>collectAstExprs(x,out)); break;
        case 'block': (s.body||[]).forEach(x=>collectAstExprs(x,out)); break;
    }
    return out;
}

function phiNeedsVariable(p, cfg, dom) {
    if(p.matDecided!==undefined) return p.matDecided;
    const vals=[...p.incoming.values()].filter(Boolean);
    let r=true;
    if(p.name==='sp' || !vals.length) r=false;
    else if(vals.every(x=>x.id===vals[0].id)) r=false;
    else if(p.condition && p.yesPred!=null && p.noPred!=null) {
        const b=cfg.blockByAddr.get(p.blockAddr);
        const loop=!!b && b.predecessors.some(q=>hasBackEdge(cfg,q,p.blockAddr,dom));
        r = loop || vals.some(x=>exprContains(x,p.id));
    }
    p.matDecided=r;
    return r;
}

function collectLivePhis(ast, cfg, dom) {
    const used=new Set(), seen=new Set();
    const visit=e=>{
        if(!e || seen.has(e.id)) return; seen.add(e.id);
        if(e.kind==='phi') {
            if(phiNeedsVariable(e,cfg,dom)) used.add(e); else visit(e.condition);
            for(const x of e.incoming.values()) visit(x);
            return;
        }
        for(const ch of exprChildren(e)) visit(ch);
    };
    for(const e of collectAstExprs(ast,[])) visit(e);
    return used;
}

function phiRefNames(e, out=new Set(), seen=new Set()) {
    if(!e || seen.has(e.id)) return out; seen.add(e.id);
    if(e.kind==='phi') {
        if(e.varName) { out.add(e.varName); return out; }
        phiRefNames(e.condition,out,seen);
        for(const x of e.incoming.values()) phiRefNames(x,out,seen);
        return out;
    }
    for(const ch of exprChildren(e)) phiRefNames(ch,out,seen);
    return out;
}

function substPhiVar(e, name, repl) {
    if(!e) return e;
    if(e.kind==='phi') return e.varName===name ? repl : e;
    if(!phiRefNames(e).has(name)) return e;
    return mapExprChildren(e,x=>substPhiVar(x,name,repl));
}

function sequenceParallelCopies(copies, df) {
    let pending=copies.filter(cp=>!(cp.expr===cp.dst || (cp.expr?.kind==='phi' && cp.expr.varName===cp.dst.varName)));
    const out=[];
    while(pending.length) {
        const idx=pending.findIndex((cp,i)=>pending.every((o,j)=>j===i || !phiRefNames(o.expr).has(cp.dst.varName)));
        if(idx>=0) {
            const cp=pending.splice(idx,1)[0];
            out.push(stmt('assign',{dst:v(cp.dst.varName),expr:cp.expr,hideTemp:false}));
            continue;
        }
        const first=pending[0];
        const tmp=`swap_${++df.swapCounter}`;
        out.push(stmt('assign',{dst:v(tmp),expr:v(first.dst.varName),hideTemp:false}));
        const tv=v(tmp);
        pending=pending.map((cp,i)=>i===0?cp:{...cp,expr:substPhiVar(cp.expr,first.dst.varName,tv)});
    }
    return out;
}

function buildPhiCopies(df, assigned) {
    for(const p of assigned) {
        if(p.varName) continue;
        const base=String(p.name||'t').replace(/[^A-Za-z0-9_]/g,'_').replace(/^_+/,'') || 't';
        const n=(df.phiNameCounts.get(base)||0)+1; df.phiNameCounts.set(base,n);
        p.varName=`v_${base}_${n}`;
    }
    const groups=new Map();
    for(const p of [...assigned].sort((a,b)=>String(a.varName).localeCompare(String(b.varName),undefined,{numeric:true}))) {
        for(const [pred,val] of p.incoming) {
            if(!val) continue;
            const key=`${pred}>${p.blockAddr}`;
            if(!groups.has(key)) groups.set(key,[]);
            groups.get(key).push({dst:p,expr:val});
        }
    }
    df.swapCounter=0;
    df.phiCopies=new Map();
    for(const [key,list] of groups) {
        const stmts=sequenceParallelCopies(list,df);
        if(stmts.length) df.phiCopies.set(key,stmts);
    }
}

function structureWithPhiLowering(cfg, df, context) {
    const dom=computeDominators(cfg);
    df.phiCopies=new Map(); df.phiNameCounts=new Map(); df.swapCounter=0;
    let ast=new Structurer(cfg,df,context).renderAST();
    const assigned=new Set();
    for(let iter=0; iter<6; iter++) {
        let changed=false;
        for(const p of collectLivePhis(ast,cfg,dom)) if(!assigned.has(p)) { assigned.add(p); changed=true; }
        if(!changed) break;
        buildPhiCopies(df,assigned);
        ast=new Structurer(cfg,df,context).renderAST();
    }
    return ast;
}

function decompileFunction(image, fn, ctxFunctions=[]) {
    const byStart=new Map(ctxFunctions.map(f=>[f.start,f]));
    const context={
        functionNameAt:(address)=>image.functionNameAt(address),
        codeSymbolAt:(address)=>image.codeSymbolAt(address),
        functionArgCountFor:(name,target)=>{
            const targetAddr=target!=null?target:image.meta.functionSymbols.find(s=>s.name===name)?.value;
            return byStart.get(targetAddr)?.argCount ?? null;
        },
        functionFPArgCountFor:(name,target)=>{
            const targetAddr=target!=null?target:image.meta.functionSymbols.find(s=>s.name===name)?.value;
            return byStart.get(targetAddr)?.fpArgCount ?? null;
        },
        functionReturnRegFor:(name,target)=>{
            const targetAddr=target!=null?target:image.meta.functionSymbols.find(s=>s.name===name)?.value;
            return byStart.get(targetAddr)?.returnReg ?? null;
        },
        currentFunctionArgCount: fn.argCount || 0,
        touchedArgRegs: new Set(fn.cfg.instructions.flatMap(i=>[...(i.operands||[]).join(' ').matchAll(/\b[xw]([0-7])\b/g)].map(m=>Number(m[1])))),
        currentFunctionFPArgCount: fn.fpArgCount || 0,
        returnReg: fn.returnReg || 'x0',
        image,
    };
    const df=new Dataflow(fn.cfg,context).run();
    const ssa=buildSSA(fn.cfg);
    const ast=normalizeASTBeforePrint(structureWithPhiLowering(fn.cfg,df,context),fn.cfg,image);
    return {
        ...fn,
        dataflow:df,
        ssa,
        ast,
        pseudo:renderFunction({name:fn.name,argCount:fn.argCount,fpArgCount:fn.fpArgCount,returnReg:fn.returnReg,cfg:fn.cfg,image,ast}),
    };
}

function summarizeCFG(fn) {
    return fn.cfg.blocks.map(b=>({
        address:b.address,
        instructions:b.instructions.map(i=>({address:i.address,word:i.word,asm:i.asm,unknown:i.unknown,relocation:i.relocation?.symbol||null})),
        predecessors:b.predecessors,
        successors:b.successors,
    }));
}

function collectStringRefs(image, fn) {
    const refs=[], seen=new Set(), regs=new Map();
    const record=(at,address)=>{
        const cands=[image.addressTarget(address)];
        if(image.pointerAt) {
            const sec=image.sectionContaining(address);
            if(sec && !/^(?:__text|__stubs|\.text)/.test(sec.sectname||sec.name||'')) {
                const ptr=image.pointerAt(address);
                if(ptr?.kind==='ptr' && ptr.value!==address) cands.push(image.addressTarget(ptr.value));
            }
        }
        for(const t of cands) {
            if(!t || !['string','cfstring','selector'].includes(t.kind)) continue;
            const key=`${at}:${t.address}`;
            if(seen.has(key)) continue; seen.add(key);
            refs.push({at,address:t.address,kind:t.kind,text:t.value});
        }
    };
    const page=a=>Math.floor(a/4096)*4096;
    for(const insn of fn.cfg.instructions) {
        const m=insn.mnemonic, o=insn.operands||[];
        let handled=false;
        if(m==='adrp' && o.length>=2) {
            const imm=parseAsmImm(o[1]);
            if(imm!=null) regs.set(canonicalReg(o[0]),page(insn.address)+imm);
            handled=true;
        } else if(m==='adr' && o.length>=2) {
            const imm=parseAsmImm(o[1]);
            if(imm!=null) { const a=insn.address+imm; regs.set(canonicalReg(o[0]),a); record(insn.address,a); }
            handled=true;
        } else if(m==='add' && o.length===3 && String(o[2]).trim().startsWith('#')) {
            const base=regs.get(canonicalReg(o[1])), imm=parseAsmImm(o[2]);
            if(base!=null && imm!=null) { const a=base+imm; regs.set(canonicalReg(o[0]),a); record(insn.address,a); handled=true; }
        } else if(/^ldr/.test(m) && o.length===2 && String(o[1]).trim().startsWith('#')) {
            const imm=parseAsmImm(o[1]);
            if(imm!=null) record(insn.address,insn.address+imm);
        } else if(/^(?:ldr|ldur|str|stur)/.test(m) && o.length>=2) {
            const mem=parseMem(o[1]);
            const base=mem && !mem.offsetReg ? regs.get(canonicalReg(mem.base)) : null;
            if(base!=null) record(insn.address,base+(mem.offset||0));
        }
        if(!handled) {
            const d=instructionRegDest(insn);
            if(d) regs.delete(canonicalReg(d));
            if(m==='bl' || m==='blr') for(let i=0;i<=18;i++) regs.delete(`x${i}`);
        }
    }
    return refs;
}

function escapeForListing(text) {
    return JSON.stringify(text.length>160 ? text.slice(0,157)+'...' : text);
}

function decompile(options) {
    const binaryPath=options.name || 'input';
    const decodeFn=options.decode
        || (typeof decodeArm64Unchecked === 'function' ? decodeArm64Unchecked : null)
        || (typeof decodeArm64 === 'function' ? (w=>decodeArm64(w,false)) : null);
    if(typeof decodeFn !== 'function') throw new Error('decode function is required (options.decode, or a global decodeArm64Unchecked / decodeArm64 from arm64.js)');
    const decoder={decodeArm64Unchecked:decodeFn};
    PRINT_STYLE = options.style === 'objc' ? 'objc' : 'c';
    PRINT_TYPES = options.types !== false;
    const image=new BinaryImage(options.bytes,options.base ?? 0,{tableNames:options.tableNames,arch:options.arch});

    let entries=null;
    if(options.functionName) {
        const sym=image.meta.functionSymbols.find(s=>s.name===options.functionName);
        if(!sym) throw new Error(`function not found: ${options.functionName}`);
        entries=[sym.value];
    } else if(Array.isArray(options.entries) && options.entries.length) {
        entries=options.entries.map(Number);
    } else if(options.entry!=null) {
        entries=[Number(options.entry)];
    } else if(options.allFunctions && image.meta.functionSymbols.length) {
        entries=image.meta.functionSymbols.map(s=>s.value);
    } else {
        entries=[image.getTextStart()];
    }

    const includeAllSymbols = !!options.allFunctions && !options.functionName && !(Array.isArray(options.entries) && options.entries.length) && options.entry == null;
    const discovered=discoverFunctions(image,decoder,{entries,includeAllSymbols,recursive:options.recursive !== false});

    const results=[];
    for(const fn of discovered.functions) {
        results.push(decompileFunction(image,fn,discovered.functions));
    }

    { const fnptrs=new Set();
      for(const r of results) for(const m of r.pseudo.matchAll(/\bglobal_([0-9a-f]+)\(/g)) fnptrs.add(m[1]);
      if(fnptrs.size) for(const r of results) r.pseudo=r.pseudo.replace(/\bglobal_([0-9a-f]+)\b/g,(m,h)=>fnptrs.has(h)?`fnptr_${h}`:m); }
    { const byStart=new Map(results.map(r=>[r.start,r])), byName=new Map(results.map(r=>[r.name,r]));
      for(const r of results) r.callers=[];
      for(const r of results) for(const cl of r.calls) {
          const callee=(cl.target!=null?byStart.get(cl.target):null) || (cl.symbol?byName.get(cl.symbol):null);
          if(callee && !callee.callers.includes(r.name)) callee.callers.push(r.name);
      } }
    for(const r of results) r.stringRefs=collectStringRefs(image,r);
    const allStrings=image.strings();

    const fmt=options.format || 'text';
    if(fmt==='json') {
        return JSON.stringify({
            input:binaryPath,
            kind:image.meta.kind,
            text:{start:image.getTextStart(),end:image.getTextEnd(),size:image.meta.text.size},
            strings:allStrings,
            functions:results.map(r=>({
                name:r.name,start:r.start,end:r.end,callCount:r.calls.length,recursive:!!r.recursive,
                argCount:r.argCount,fpArgCount:r.fpArgCount||0,returnReg:r.returnReg||'x0',
                calls:r.calls,callers:r.callers,stringRefs:r.stringRefs,cfg:summarizeCFG(r),ssa:summarizeSSA(r.ssa),pseudo:r.pseudo,
            })),
        },jsonReplacer,2);
    }

    const lines=[];
    lines.push(`input: ${binaryPath}`);
    lines.push(`format: ${image.meta.kind}`);
    lines.push(`text: ${hex64(image.getTextStart())}..${hex64(image.getTextEnd())}`);
    lines.push(`functions analyzed: ${results.length}`);
    lines.push('');
    if(allStrings.length) {
        lines.push(`strings (${allStrings.length}):`);
        for(const st of allStrings) lines.push(`  ${hex64(st.address)}  ${st.section.padEnd(16)} ${escapeForListing(st.text)}`);
        lines.push('');
    }
    for(let i=0;i<results.length;i++) {
        const r=results[i];
        lines.push(`=== ${r.name} @ ${hex64(r.start)}..${hex64(r.end)} ===`);
        lines.push(`instructions: ${r.cfg.instructions.length}, blocks: ${r.cfg.blocks.length}, calls: ${r.calls.length}${r.recursive?' [recursive]':''}`);
        for(const b of r.cfg.blocks) {
            lines.push(`L_${b.address.toString(16)}:`);
            for(const ins of b.instructions) lines.push(`  ${hex64(ins.address)}  ${ins.asm}${ins.relocation?.symbol?`  ; reloc ${ins.relocation.symbol}`:''}`);
            if(b.successors.length) lines.push(`  -> ${b.successors.map(s=>s.symbol?`${s.symbol}`:`L_${s.address.toString(16)}${s.type==='true'?' [T]':s.type==='false'?' [F]':''}`).join(', ')}`);
        }
        lines.push('');
        lines.push(`called by: ${r.callers.length ? r.callers.join(', ') : '(none found)'}`);
        if(r.stringRefs.length) {
            lines.push('--- string references ---');
            for(const x of r.stringRefs) lines.push(`  ${hex64(x.at)} -> ${hex64(x.address)} ${'str '}${escapeForListing(x.text)}`);
            lines.push('');
        }
        lines.push('--- --- decompile --- ---');
        lines.push(r.pseudo);
        lines.push('');
    }
    return lines.join('\n');
}

function jsonReplacer(key,value) {
    if(key==='dataflow') return undefined;
    if(key==='df') return undefined;
    return value;
}
