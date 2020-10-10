#define _CRT_SECURE_NO_WARNINGS
#include "159156_elf.h"
#include<iostream>
#include<fstream>
#include<Windows.h>

#define soFileName "D:\\Visual_Studio_Repos_2013\\knowWhatElf\\knowWhatElf\\libhello-jni.so"
#define ALIGN(P, ALIGNBYTES)  (((unsigned long)P + ALIGNBYTES -1)&~(ALIGNBYTES-1)) //求出剩余数据的起始位置

using namespace std;

// 文件读取到内存
void MyReadFile(PVOID* pSoFile){
	DWORD dwSoBufferSize = 0;
	fstream fs(soFileName, ios::in | ios::binary);
	if(fs.fail())
		return;
	fs.seekg(0, ios::end);
	int filesize = fs.tellg();
	fs.seekg(0, ios::beg);
	*pSoFile = new byte[filesize];
	fs.read((char*)*pSoFile, filesize);
	fs.close();
}

// 新增节
int addSectionFun(char *lpPath, char *szSecname, unsigned int nNewSecSize)
{
	char name[50];
	FILE *fdr, *fdw;
	char *base = NULL;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *t_phdr, *load1, *load2, *dynamic;
	Elf32_Shdr *s_hdr;
	int flag = 0;
	int i = 0;
	unsigned mapSZ = 0;
	unsigned nLoop = 0;
	unsigned int nAddInitFun = 0;
	unsigned int nNewSecAddr = 0;
	unsigned int nModuleBase = 0;
	memset(name, 0, sizeof(name));
	if (nNewSecSize == 0)
	{
		return 0;
	}
	fopen_s(&fdr, lpPath, "rb");
	strcpy(name, lpPath);
	if (strchr(name, '.'))
	{
		strcpy(strchr(name, '.'), "_new.so");
	}
	else
	{
		strcat(name, "_new");
	}
	fdw = fopen(name, "wb");
	if (fdr == NULL || fdw == NULL)
	{
		printf("Open file failed");
		return 1;
	}
	fseek(fdr, 0, SEEK_END);
	mapSZ = ftell(fdr);//源文件的长度大小
	printf("mapSZ:0x%x\n", mapSZ);

	base = (char*)malloc(mapSZ * 2 + nNewSecSize);//2*源文件大小+新加的Section size，这里不懂为什么需要*2
	printf("base 0x%x \n", base);

	memset(base, 0, mapSZ * 2 + nNewSecSize);
	fseek(fdr, 0, SEEK_SET);
	fread(base, 1, mapSZ, fdr);//拷贝源文件内容到base
	if (base == (void*)-1)
	{
		printf("fread fd failed");
		return 2;
	}

	//判断Program Header
	ehdr = (Elf32_Ehdr*)base;
	t_phdr = (Elf32_Phdr*)(base + sizeof(Elf32_Ehdr)); // 通过偏移拿到program header第一个结构体 PT_PHDR结构体

	for (i = 0; i<ehdr->e_phnum; i++) //开始遍历program header结构体
	{
		if (t_phdr->p_type == PT_LOAD)
		{
			//这里的flag只是一个标志位，去除第一个LOAD的Segment的值
			if (flag == 0)
			{
				load1 = t_phdr;
				flag = 1;
				nModuleBase = load1->p_vaddr;
				printf("load1 = %p, offset = 0x%x \n", load1, load1->p_offset);
			}
			else
			{
				load2 = t_phdr;
				printf("load2 = %p, offset = 0x%x \n", load2, load2->p_offset);
			}
		}
		if (t_phdr->p_type == PT_DYNAMIC)
		{
			dynamic = t_phdr;
			printf("dynamic = %p, offset = 0x%x \n", dynamic, dynamic->p_offset);
		}
		t_phdr++;
	}

	
	s_hdr = (Elf32_Shdr*)(base + ehdr->e_shoff); //拿到section header的首地址
	
	//获取到新加section的位置，这个是重点,需要进行页面对其操作
	printf("addr:0x%x\n", load2->p_paddr);
	nNewSecAddr = ALIGN(load2->p_paddr + load2->p_memsz - nModuleBase, load2->p_align); //计算出load2的对齐大小，在对齐大小后面的地址进行操作手
	printf("new section add:%x \n", nNewSecAddr);

	if (load1->p_filesz < ALIGN(load2->p_paddr + load2->p_memsz, load2->p_align))
	{
		printf("offset:%x\n", (ehdr->e_shoff + sizeof(Elf32_Shdr) * ehdr->e_shnum));
		//注意这里的代码的执行条件，这里其实就是判断section header是不是在文件的末尾
		if ((ehdr->e_shoff + sizeof(Elf32_Shdr) * ehdr->e_shnum) != mapSZ)
		{
			if (mapSZ + sizeof(Elf32_Shdr) * (ehdr->e_shnum + 1) > nNewSecAddr)
			{
				printf("无法添加节\n");
				return 3;
			}
			else
			{
				memcpy(base + mapSZ, base + ehdr->e_shoff, sizeof(Elf32_Shdr) * ehdr->e_shnum);//将Section Header拷贝到原来文件的末尾
				ehdr->e_shoff = mapSZ;
				mapSZ += sizeof(Elf32_Shdr) * ehdr->e_shnum;//加上Section Header的长度
				s_hdr = (Elf32_Shdr*)(base + ehdr->e_shoff);
				printf("ehdr_offset:%x", ehdr->e_shoff);
			}
		}
	}
	else
	{
		nNewSecAddr = load1->p_filesz;
	}
	printf("还可添加 %d 个节\n", (nNewSecAddr - ehdr->e_shoff) / sizeof(Elf32_Shdr) - ehdr->e_shnum - 1);

	int nWriteLen = nNewSecAddr + ALIGN(strlen(szSecname) + 1, 0x10) + nNewSecSize;//添加section之后的文件总长度：原来的长度 + section name + section size
	printf("write len %x\n", nWriteLen);
	
	char* lpWriteBuf = (char*)malloc(nWriteLen);//nWriteLen :最后文件的总大小
	memset(lpWriteBuf, 0, nWriteLen);

	//ehdr->e_shstrndx是section name的string表在section表头中的偏移值,修改string段的大小
	s_hdr[ehdr->e_shstrndx].sh_size = nNewSecAddr - s_hdr[ehdr->e_shstrndx].sh_offset + strlen(szSecname) + 1;
	strcpy(lpWriteBuf + nNewSecAddr, szSecname);//添加section name

	//以下代码是构建一个Section Header
	Elf32_Shdr newSecShdr = { 0 };
	newSecShdr.sh_name = nNewSecAddr - s_hdr[ehdr->e_shstrndx].sh_offset;
	newSecShdr.sh_type = SHT_PROGBITS;
	newSecShdr.sh_flags = SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR;
	nNewSecAddr += ALIGN(strlen(szSecname) + 1, 0x10);
	newSecShdr.sh_size = nNewSecSize;
	newSecShdr.sh_offset = nNewSecAddr;
	newSecShdr.sh_addr = nNewSecAddr + nModuleBase;
	newSecShdr.sh_addralign = 4;

	//修改Program Header信息
	load1->p_filesz = nWriteLen;
	load1->p_memsz = nNewSecAddr + nNewSecSize;
	load1->p_flags = 7;		//可读 可写 可执行

	//修改Elf header中的section的count值
	ehdr->e_shnum++;
	memcpy(lpWriteBuf, base, mapSZ);//从base中拷贝mapSZ长度的字节到lpWriteBuf
	memcpy(lpWriteBuf + mapSZ, &newSecShdr, sizeof(Elf32_Shdr));//将新加的Section Header追加到lpWriteBuf末尾

	//写文件
	fseek(fdw, 0, SEEK_SET);
	fwrite(lpWriteBuf, 1, nWriteLen, fdw);
	fclose(fdw);
	fclose(fdr);
	free(base);
	free(lpWriteBuf);
	return 0;
}

void getElfHeader(PVOID pSoFile){
	elf32_hdr* pElf32_hdr = NULL;
	pElf32_hdr = (elf32_hdr*)pSoFile;
	printf("Magic: ");
	for (DWORD i = 0;i<16;i++){
		printf("%02X ", *(PBYTE)&pElf32_hdr->e_ident[i]);
	}
	printf("\n");
	printf("e_type: 0x%X\n", pElf32_hdr->e_type);
	printf("e_machine: 0x%X\n", pElf32_hdr->e_machine);
	printf("e_version: 0x%X\n", pElf32_hdr->e_version);
	printf("e_entry: 0x%X\n", pElf32_hdr->e_entry);
	printf("e_phoff（Program Headers Offset）: 0x%X\n", pElf32_hdr->e_phoff);
	printf("e_shoff（Section Headers Offset）: 0x%X\n", pElf32_hdr->e_shoff);
	printf("e_flags: 0x%X\n", pElf32_hdr->e_flags);
	printf("e_ehsize: 0x%X\n", pElf32_hdr->e_ehsize);
	printf("e_phentsize: 0x%X\n", pElf32_hdr->e_phentsize);
	printf("e_phnum: 0x%X\n", pElf32_hdr->e_phnum);
	printf("e_shentsize: 0x%X\n", pElf32_hdr->e_shentsize);
	printf("e_shnum: 0x%X\n", pElf32_hdr->e_shnum);
	printf("e_shstrndx: 0x%X\n", pElf32_hdr->e_shstrndx);
}

void getSectionHeader_dynsym(PVOID pSoFile){
	elf32_hdr* pElf32_hdr = NULL;
	elf32_shdr* pElf32_shdr = NULL;
	elf32_shdr* pElf32_shdr_shstrtab = NULL;
	elf32_shdr* pElf32_shdr_dynsym = NULL;
	elf32_sym* pElf32_dynsym = NULL;
	PVOID pElf32_dymstr = NULL;
	DWORD dwIndexDynstr = 0;
	DWORD dwCount = 0;

	pElf32_hdr = (elf32_hdr*)pSoFile;
	pElf32_shdr = (elf32_shdr*)((DWORD)pSoFile + (DWORD)pElf32_hdr->e_shoff);
	pElf32_shdr_shstrtab = (elf32_shdr*)&pElf32_shdr[pElf32_hdr->e_shnum - 1];

	for (DWORD i = 0; i<pElf32_hdr->e_shnum; i++){		
		// printf("%s \n", (char*)((DWORD)pSoFile + (DWORD)pElf32_shdr_shstrtab->sh_offset + pElf32_shdr[i].sh_name));
		if (strcmp((char*)((DWORD)pSoFile + (DWORD)pElf32_shdr_shstrtab->sh_offset + pElf32_shdr[i].sh_name), ".dynsym") == 0){
			
			dwCount = pElf32_shdr[i].sh_size / pElf32_shdr[i].sh_entsize; //dwCount表示符号表dynsym中的项目数量
			printf("Symbol table '.dynsym' contains %d entries \n", dwCount);

			//还得获取符号表字符串.synstr的表的首地址
			for (DWORD m = 0; m<pElf32_hdr->e_shnum; m++){
				if (strcmp((char*)((DWORD)pSoFile + (DWORD)pElf32_shdr_shstrtab->sh_offset + pElf32_shdr[m].sh_name), ".dynstr") == 0){
					dwIndexDynstr = m;
					break;
				}
			}
			pElf32_dymstr = (PVOID)((DWORD)pSoFile + (DWORD)pElf32_shdr[dwIndexDynstr].sh_offset); //确认符号表字符串获取成功
			
			for (DWORD j = 0; j < dwCount; j++){
				pElf32_dynsym = (elf32_sym*)((DWORD)pSoFile + pElf32_shdr[i].sh_offset);
				//printf("%x\n", pElf32_dynsym[j].st_name);
				printf("%s \n", (PCHAR)((DWORD)pElf32_dymstr + (DWORD)pElf32_dynsym[j].st_name));
			}

			break;
		}
	}
	
}

void getProgramHeader(PVOID pSoFile){
	elf32_hdr* pElf32_hdr = NULL;
	elf32_phdr* pElf32_phdr = NULL;
	pElf32_hdr = (elf32_hdr*)pSoFile;
	pElf32_phdr = (elf32_phdr*)((DWORD)pSoFile + (DWORD)pElf32_hdr->e_phoff);

	for (DWORD i = 0; i < pElf32_hdr->e_phnum; i++){
		printf("p_type: 0x%x\n", pElf32_phdr[i].p_type);
		printf("p_offset: 0x%x\n", pElf32_phdr[i].p_offset);
		printf("p_vaddr: 0x%x\n", pElf32_phdr[i].p_vaddr);
		printf("p_paddr: 0x%x\n", pElf32_phdr[i].p_paddr);
		printf("p_filesz: 0x%x\n", pElf32_phdr[i].p_filesz);
		printf("p_memsz: 0x%x\n", pElf32_phdr[i].p_memsz);
		printf("p_flags: 0x%x\n", pElf32_phdr[i].p_flags);
		printf("p_filesz: 0x%x\n", pElf32_phdr[i].p_filesz);
		printf("\n");
	}

}

int main(){
	PVOID pSoFile;
	MyReadFile(&pSoFile);
	//getElfHeader(pSoFile);
	//getSectionHeader_dynsym(pSoFile);
	getProgramHeader(pSoFile);
	//addSectionFun("C:\\Users\\dell\\Desktop\\libhello-jni.so", ".zpchcbd", 0x1000);
	return 0;
}