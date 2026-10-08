# python3 sheet.py out.png still1.png still2.png ... -> 3-column contact sheet with timestamps
import sys,re,subprocess
out,files=sys.argv[1],sys.argv[2:]
tt=lambda f:re.search(r't-(\d+\.\d+)',f).group(1)
args=[]
for f in files: args+=['-i',f]
n=len(files); cols=3
flt=''.join(f"[{i}:v]scale=640:360[v{i}];" for i,f in enumerate(files))
lay='|'.join(f'{(i%cols)*640}_{(i//cols)*360}' for i in range(n))
flt+=''.join(f'[v{i}]' for i in range(n))+f'xstack=inputs={n}:layout={lay}:fill=black'
subprocess.run(['ffmpeg','-loglevel','error','-y',*args,'-filter_complex',flt,out],check=True)
