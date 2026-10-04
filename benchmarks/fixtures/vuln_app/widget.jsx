export function Widget({ answer }) {
  return <div dangerouslySetInnerHTML={{ __html: answer }} />;
}
